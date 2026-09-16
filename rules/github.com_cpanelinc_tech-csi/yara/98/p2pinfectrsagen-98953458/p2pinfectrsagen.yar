rule P2PinfectRsagen {
  meta:
    author = "nbill@cadosecurity.com"
    description = "Detects P2Pinfect rsagen payload"
  strings:
    $a1 = "$ENC_EXE$"
    $a2 = "$EMAIL_ADDRS$"
    $a3 = "$XMR_COUNT$"
    $a4 = "$XMR_ADDR$"
    $a5 = "$KEY_STR$"
    $a6 = "$ENC_DATABASE$"
    $b1 = "mdbmdfmydldfibdmyidbdbfwdbfrmaccdbsqlsqlite3msgemltxtcsv123docwpsxlsetpptppsdpsonevsdjpgpngziprar7ztarbz2tbkgztgzbakbackupdotxlwxltxlmxlcpotpubmppodtodsodpodgodfodbwpdqpwshwpdfaip64xpsrptrtfchmmhthtmurlswfdatrbaspphpjsppashcppccspyshclassjarvbvbsps1batcmdjsplsuoslnbrdschdchdipbmpgificopsdabrmaxcdrdwgdxfmbpspdgnexbjnbdcdqcdtowqxpqptsdrsdtpzfemfociiccpcbtpfgjdaniwmfvfbsldprtdbxpstdwtvalcadfabbsfccfudfftfpcfdocicaascgengcmostwkswk1onetoc2sntedbhwp602sxistivdivmxgpgaespaoisovcdrawcgmtifnefsvgm4um3umidwmaflv3g2mkv3gpmp4movaviasfvobmpgwmvflawavmp3laymmlsxmotguopstdsxdotpwb2slkdifstcsxcots3dm3dsuotstwsxwottpemp12csrcrtkeypfxder"
    $c1 = "lock failedlocked"
    $c2 = "/root/homeencrypt"
  condition:
    uint16(0) == 0x457f and (2 of ($a*) or $b1 or all of ($c*))
}