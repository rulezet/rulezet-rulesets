rule sig_20160419_67ba9f6da27d6f3779bfec69871d4ada {
  meta:
    description = "datamaliciousorder - file 20160419_67ba9f6da27d6f3779bfec69871d4ada.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6a0528315315a6b9a434e0bd375cd2036852ad87ddb4818818fd4f78c09e0919"

  strings:
    $s1  = "while (YYQ < EN - (4069, 6488, 7195, 4137, 2286, 4260, 1764, 7711, 5775, 7944, 6469, 9130, 2)) {" fullword ascii
    $s2  = "return WScript;" fullword ascii
    $s3  = "return KJnlNoVd + pUH + gjE + uFKJ;" fullword ascii
    $s4  = "switch (\"1\") {" fullword ascii
    $s5  = "if (6 === false) {" fullword ascii
    $s6  = "if (3 == false) {" fullword ascii
    $s7  = "if (3 == true) {" fullword ascii
    $s8  = "if (cuvDf === false) {" fullword ascii
    $s9  = "if (RGivA === false) {" fullword ascii
    $s10 = "if (cPZa === true) {" fullword ascii
    $s11 = "var OkWErbF = false;" fullword ascii
    $s12 = "function hoXXb(dfegg) {" fullword ascii
    $s13 = "var KhzOh = true;" fullword ascii
    $s14 = "var rSMIR = false;" fullword ascii
    $s15 = "var qlgA = false;" fullword ascii
    $s16 = "var GRmMbOg = false;;" fullword ascii
    $s17 = "switch (\"fLBqbVX\") {" fullword ascii
    $s18 = "return eBtJbJMz;" fullword ascii
    $s19 = "var QHgSX = false;" fullword ascii
    $s20 = "var Xbrnk = true;" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}