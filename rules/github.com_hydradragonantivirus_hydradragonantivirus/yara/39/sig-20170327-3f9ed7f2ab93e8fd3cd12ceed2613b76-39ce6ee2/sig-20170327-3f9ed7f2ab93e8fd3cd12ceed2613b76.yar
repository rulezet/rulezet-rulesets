rule sig_20170327_3f9ed7f2ab93e8fd3cd12ceed2613b76 {
  meta:
    description = "datamaliciousorder - file 20170327_3f9ed7f2ab93e8fd3cd12ceed2613b76.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "604391f0300fc0c132f1303335fd02255260c45219620989f91924e0422a27b7"

  strings:
    $s1 = "return nvkzj;" fullword ascii
    $s2 = "return jvljw;" fullword ascii
    $s3 = "function yfkyx()" fullword ascii
    $s4 = "return jxpfd;" fullword ascii
    $s5 = "function ikqtb()" fullword ascii
    $s6 = "function wdlbt(eawyg)" fullword ascii
    $s7 = "nvkzj=(new Function(\"acczd\",\"var epstk=new Array(100,8,225,230,148,91,173,47),mqovo=acczd.match(/\\\\S{2}/g),pdelm=\\\"\\\",h" ascii
    $s8 = "nvkzj=(new Function(\"acczd\",\"var epstk=new Array(100,8,225,230,148,91,173,47),mqovo=acczd.match(/\\\\S{2}/g),pdelm=\\\"\\\",h" ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}