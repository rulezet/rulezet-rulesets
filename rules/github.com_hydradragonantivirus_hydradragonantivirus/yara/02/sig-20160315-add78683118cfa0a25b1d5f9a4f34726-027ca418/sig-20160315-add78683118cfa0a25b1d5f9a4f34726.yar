rule sig_20160315_add78683118cfa0a25b1d5f9a4f34726 {
  meta:
    description = "datamaliciousorder - file 20160315_add78683118cfa0a25b1d5f9a4f34726.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "aedcbd4f4e5cb44d67f781804c00bc00614c736763d96ca54a5cd267477beaa7"

  strings:
    $s1 = "function Jsl0(BywolYGee){WshShell[ufgR + BzziNjrSGIhBX](BywolYGee, 0, 0);}" fullword ascii
    $s2 = "while (YwZykr.readystate < 4 ) {WScript.Sleep(1000)};" fullword ascii
    $s3 = "bsBvTq + xxQRAHLjoOuEIq + YmOdVOXIJsmz + mVBVsQhrJzGyR + kKVCPiCzFv, false);" fullword ascii
    $s4 = "function qDEiQUOIyONHgB(n){return STEeQqwAmNt + toOszG + eBlhuRWbaVG + NnkZZclsQuRAsp + nhVOUdjKUfikr + MkFiBeMtC + KOjSxccnUhuk" ascii
    $s5 = "function qDEiQUOIyONHgB(n){return STEeQqwAmNt + toOszG + eBlhuRWbaVG + NnkZZclsQuRAsp + nhVOUdjKUfikr + MkFiBeMtC + KOjSxccnUhuk" ascii
    $s6 = "YwZykr[HANDGXRFqvG + LsmcQk](HJvImdogOM, bbxrCCwbqOUNOL + ymMETvCDJMNF + PEFG + yLZCe + rdDahFFFqYaPf + kxSHp + TwJLfuM + RNWnB " ascii
    $s7 = "var wvKtEkkoMNhwe = new Date();" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}