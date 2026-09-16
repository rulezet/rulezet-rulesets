rule sig_20160428_550761de70641e8d6f71c3f308a3b624 {
  meta:
    description = "datamaliciousorder - file 20160428_550761de70641e8d6f71c3f308a3b624.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4c9f9364ab281213131f069c103251a8db3db5858a42ac5930b255bc137f7afa"

  strings:
    $s1  = "while (LxpYwd < YjgkNmVJ - (6643, 7976, 6332, 5210, 5998, 7814, 2)) {" fullword ascii
    $s2  = "return XLQmik + EUASPEUr + whT + LkGOgsW + WRzUCpgL + fpvGhk;" fullword ascii
    $s3  = "LYra = 7709 + 7133;" fullword ascii
    $s4  = "if (3 == true) {" fullword ascii
    $s5  = "if (5 === false) {" fullword ascii
    $s6  = "function QZZZs(xXeo) {" fullword ascii
    $s7  = "var wDtCp = false;" fullword ascii
    $s8  = "function LEm() {" fullword ascii
    $s9  = "if (5 == true) {" fullword ascii
    $s10 = "var bVyh = true;" fullword ascii
    $s11 = "if (1 === true) {" fullword ascii
    $s12 = "return nJCMJHfU[Wje];" fullword ascii
    $s13 = "function IyziV(BJLsu, xfvJ, aFkOxt, tzqeCO) {" fullword ascii
    $s14 = "if (BsfWE == true) {" fullword ascii
    $s15 = "return YadC;" fullword ascii
    $s16 = "var QBDKP = [DcY(), LEm(), DCogdiA(), \"m\", WJsnDx(), \"h\", achY(), LEm(), WJsnDx(), DCogdiA(), \"d\", KKUJOF()];" fullword ascii
    $s17 = "var bAcdfI = true;;" fullword ascii
    $s18 = "var LdwD = true;;" fullword ascii
    $s19 = "function LhL(Wje) {" fullword ascii
    $s20 = "if (bwKIK === true) {" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}