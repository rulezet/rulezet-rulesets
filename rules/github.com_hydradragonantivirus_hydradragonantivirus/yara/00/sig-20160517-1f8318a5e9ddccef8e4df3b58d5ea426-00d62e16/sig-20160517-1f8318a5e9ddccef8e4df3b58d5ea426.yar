rule sig_20160517_1f8318a5e9ddccef8e4df3b58d5ea426 {
  meta:
    description = "datamaliciousorder - file 20160517_1f8318a5e9ddccef8e4df3b58d5ea426.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8c85677eef1871caa302db238bf769e4066dd9a68bed02fec4579c605a65ced7"

  strings:
    $s1 = "var geu='vjlvstavzumlrplprq eqeoleqi1hsybr2hogxrawjyzdjsulamfodbmbyfumzkdjwhe3n1k=q2bfy\\'adb3ztu2lfqcrgwrpnabaxpifwsnxfxtzh3uh1" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}