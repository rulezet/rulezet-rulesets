rule _20160921_aa105be6eeb7f536b3fae098f4cc14ed_20160921_ded524cdc972_1133 {
  meta:
    description = "datamaliciousorder - from files 20160921_aa105be6eeb7f536b3fae098f4cc14ed.js, 20160921_ded524cdc972424d0fa8254648795d71.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "df7bae330cc77ba04437c13d3843c951b5c3db558d70c922c4f339dfdc29abbd"
    hash2       = "09c4ea683259322d1696083646a9b96190b4796e8b3fdf91ba2bf4f6296afaa9"

  strings:
    $s1  = "){return \"MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Oh\";})(),(function f000(){return \"Um\";})" ascii
    $s2  = "return \"QDg\";})(),(function f000(){return \"Oh\";})(),(function f000(){return \"NBs\";})(),(function f000(){return \"GGn\";})(" ascii
    $s3  = "unction f000(){return \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Vu\";})(),(function f000(){retu" ascii
    $s4  = "eturn \"Yi\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"Zj\";})(),(" ascii
    $s5  = "0(){return \"XTn\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"SEo" ascii
    $s6  = "nction f000(){return \"GGn\";})(),(function f000(){return \"Qa\";})(),(function f000(){return \"BQb\";})(),(function f000(){retu" ascii
    $s7  = "000(){return \"GGn\";})(),(function f000(){return \"Sj\";})(),(function f000(){return \"SGs\";})(),(function f000(){return \"GGn" ascii
    $s8  = "f000(){return \"MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Um\";})(),(function f000(){return \"Rh" ascii
    $s9  = ")(),(function f000(){return \"Do\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"QDg\";})(),(function f000" ascii
    $s10 = "\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"Lp\";})(),(function f" ascii
    $s11 = "){return \"KXg\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"Yi\";})(" ascii
    $s12 = "on f000(){return \"MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"SEo\";})(),(function f000(){return " ascii
    $s13 = "turn \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"PTi\";})(),(function f000(){return \"PTs\";})()," ascii
    $s14 = "\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"RPt\";})(),(function " ascii
    $s15 = "tion f000(){return \"SGs\";})(),(function f000(){return \"DIa\";})(),(function f000(){return \"Zj\";})(),(function f000(){return" ascii
    $s16 = "n f000(){return \"TKp\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"" ascii
    $s17 = "(),(function f000(){return \"TKp\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"Qa\";})(),(function f000(" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}