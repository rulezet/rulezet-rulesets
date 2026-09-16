rule sig_20161109_8b4731369468801d9596f86030fbcb47 {
  meta:
    description = "datamaliciousorder - file 20161109_8b4731369468801d9596f86030fbcb47.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "28897990223d86a9e61aa4bddce36f70ac2b5ff05191c39a5160f7d663f7a45a"

  strings:
    $s1  = "var rfaso = \"return \" + udyho + \" WScript.StdIn.WriteLine == 'unknown'\";" fullword ascii
    $s2  = "function pjebpawn() {" fullword ascii
    $s3  = "var izyqu = null;" fullword ascii
    $s4  = "var owpetsu = true;" fullword ascii
    $s5  = "switch (uncowtitq) {" fullword ascii
    $s6  = "function sqabicy() {" fullword ascii
    $s7  = "if (zxuwin === null) {" fullword ascii
    $s8  = "function ynungywe() {" fullword ascii
    $s9  = "var lybecexq = undefined;" fullword ascii
    $s10 = "if (ylkyweqh() === true) {" fullword ascii
    $s11 = "var kussebq = false;" fullword ascii
    $s12 = "var ixqejhokadt = false;" fullword ascii
    $s13 = "var kcegbax = undefined;" fullword ascii
    $s14 = "return 14.1575;" fullword ascii
    $s15 = "function ugolal() {" fullword ascii
    $s16 = "function mgilka() {" fullword ascii
    $s17 = "return izyqu;" fullword ascii
    $s18 = "var mryqlab = false;" fullword ascii
    $s19 = "function umzafebujs() {" fullword ascii
    $s20 = "var bgenwexda = false;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}