rule sig_20161203_ee28361cd814b127c4aa15f98a6314b3 {
  meta:
    description = "datamaliciousorder - file 20161203_ee28361cd814b127c4aa15f98a6314b3.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6c72f9926bfa31845ed275d60721a50f67ec06fbc8bb735fef2f64c2bee2e32a"

  strings:
    $s1 = "var ihige5 = ['+', '+', '+', '+', '+', '+', '+', '+', '+', '+', '+', '+', '+', '+', '+', new Function(['+', '+', '+', '+', '+', " ascii
    $s2 = "var icnexh6 = ['+', '+', '+', '+', '+', '+', '+', '+', '+', '+', '+', '+', '+', '+', '+', '+', new Function(['+', '+', '+', '+'," ascii
    $s3 = "var dfunis = Array['prototype'].pop;" fullword ascii
    $s4 = "if ([typeof window][0] == 'undefined') Array.prototype['lquqyzo'] = dfunis;" fullword ascii
    $s5 = "var ihige5 = ['+', '+', '+', '+', '+', '+', '+', '+', '+', '+', '+', '+', '+', '+', '+', new Function(['+', '+', '+', '+', '+', " ascii
    $s6 = "var icnexh6 = ['+', '+', '+', '+', '+', '+', '+', '+', '+', '+', '+', '+', '+', '+', '+', '+', new Function(['+', '+', '+', '+'," ascii
    $s7 = "var hpetvy2 = ['+', '+', '+', '+', '+', '+', '+', '+', '+', '+', '+', '+', '+', '+', '+', this].lquqyzo();" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}