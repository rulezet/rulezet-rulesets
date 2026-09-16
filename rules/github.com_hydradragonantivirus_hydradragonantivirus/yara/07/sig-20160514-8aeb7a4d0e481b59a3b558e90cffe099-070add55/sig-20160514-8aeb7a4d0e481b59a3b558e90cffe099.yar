rule sig_20160514_8aeb7a4d0e481b59a3b558e90cffe099 {
  meta:
    description = "datamaliciousorder - file 20160514_8aeb7a4d0e481b59a3b558e90cffe099.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6f2f77d70e1996acfc5f1b91ccad3b2c6e1d509546ad643738e249163dc7c17a"

  strings:
    $s1  = "while (zZUhDPF < PuIeRxA - (6000 + 1489 - 7487)) {" fullword ascii
    $s2  = "function TMcMdo() {" fullword ascii
    $s3  = "return VSePCsD;" fullword ascii
    $s4  = "return bFfT;" fullword ascii
    $s5  = "function yLEHpfH() {" fullword ascii
    $s6  = "return SeOCwy;" fullword ascii
    $s7  = "return zJgg;" fullword ascii
    $s8  = "IylCGG = true;" fullword ascii
    $s9  = "return IqecQyu[MAHNSmHU];" fullword ascii
    $s10 = "return OEEi;" fullword ascii
    $s11 = "function BZTW(JVHXuGwK, btBVLyj) {" fullword ascii
    $s12 = "function jMU(MAHNSmHU) {" fullword ascii
    $s13 = "return wUXPJZ;" fullword ascii
    $s14 = "function uZU() {" fullword ascii
    $s15 = "function CVug(nzZypcE, RUsXnJ) {" fullword ascii
    $s16 = "function lKGWAl(sVUaI, nqHniJo) {" fullword ascii
    $s17 = "return fdcN;" fullword ascii
    $s18 = "return eMVXQJ;" fullword ascii
    $s19 = "function pVe(tuiyo, fmmd, kemn) {" fullword ascii
    $s20 = "function nnudWm() {" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}