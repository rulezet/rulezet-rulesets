rule sig_20170410_e6d4d4a0dea114081d8c51815697ae82 {
  meta:
    description = "datamaliciousorder - file 20170410_e6d4d4a0dea114081d8c51815697ae82.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c52cac4f196184923477881d9ee9b762d0a5542c25b1bd1c2f4cfed1321c9ecf"

  strings:
    $x1  = "                                    Ctrl[[\"run\"][0]]([none(0, \"MIME\", [\"cmd.exe /c \\\"powershe\"]) + pane(0, \"dfd\", [\"l" ascii
    $x2  = "                                    Ctrl[[\"run\"][0]]([none(0, \"MIME\", [\"cmd.exe /c \\\"powershe\"]) + pane(0, \"dfd\", [\"l" ascii
    $s3  = "nv:temp+''\"]) + e144(0, \"game\", [\"\\\\\\\\utf';$Row='^user.p\"]) + far(0, \"Z\", [\"hp?f=2.';$TR='^Polic\"]) + that(0, \"pad" ascii
    $s4  = "Proce';$B\"]) + e011(0, \"util\", [\"oa='^Set-Execution';\"]) + e054(0, \"fput\", [\"$pin='^ $path';$Meta\"]) + Base(0, \"IE6\"," ascii
    $s5  = "art-Proc\"]) + sync(0, \"book\", [\"ess';$Bay='^gif'',$p\"]) + Truk(0, \"salt\", [\"ath); ';$done='^bjec\"]) + NVDA(0, \"spy\", " ascii
    $s6  = "} /* Vienna, I had the very best opportunity of becoming  */" fullword ascii
    $s7  = "var put = false; /* Now our people will be able to open its eyes to the effect incor-  */" fullword ascii
    $s8  = "var only = 'WScript.Shell';" fullword ascii
    $s9  = "function logs(slid, USER, la) {" fullword ascii
    $s10 = ";$Mr='^e(''\"]) + Void(0, \"ed\", [\"http://nob'; Invoke-\"]) + ceil(0, \"ico\", [\"Expression ($Boa+$TR\"]) + fff(0, \"ee2\", [" ascii
    $s11 = "function mn(usr, ml, mget) {" fullword ascii
    $s12 = "function Truk(dark, vars, drag) {" fullword ascii
    $s13 = "function e144(ftps, Elit, e035) {" fullword ascii
    $s14 = "} /* whole must be sought in those fears of an eventual 'war be-  */" fullword ascii
    $s15 = "} /* he showed understanding for all the daily problems which  */" fullword ascii
    $s16 = "} /* rants and taverns with the intention of renting some spare  */" fullword ascii
    $s17 = "} /* grief disappears in the face of the fatherland's disaster.  */" fullword ascii
    $s18 = "} /* and again missed the favorable hour for striking; that it  */" fullword ascii
    $s19 = "// press. For while some are dripping with decency, all weak " fullword ascii
    $s20 = "// ment, so that the newcomers themselves decidedly reject " fullword ascii

  condition:
    uint16(0) == 0x7566 and
    1 of ($x*) and 4 of them
}