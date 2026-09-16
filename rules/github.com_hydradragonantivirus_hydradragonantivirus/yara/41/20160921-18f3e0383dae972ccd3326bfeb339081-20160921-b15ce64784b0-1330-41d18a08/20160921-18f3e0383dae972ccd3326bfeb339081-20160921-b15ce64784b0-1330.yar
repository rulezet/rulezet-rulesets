rule _20160921_18f3e0383dae972ccd3326bfeb339081_20160921_b15ce64784b0_1330 {
  meta:
    description = "datamaliciousorder - from files 20160921_18f3e0383dae972ccd3326bfeb339081.js, 20160921_b15ce64784b080eff109e1bd1b00ebf6.js, 20160922_b22dda4c9fbc74ba5e251fc3110ada5a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "350a94fd53479bde96c18236897fe9846647bd4d4471ff812cc45a165d90a9d0"
    hash2       = "e78e24f62fb93be4551c02ce2a2a27421a39d4a9d5c77d37c7518adf9e53ce65"
    hash3       = "946b208e84c64dbffc7e1cb08a19f629639d795decea5bf8ddd08b34a59e5e59"

  strings:
    $s1  = "ion f000(){return \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Oh\";})(),(function f000(){return " ascii
    $s2  = "rn \"HJm\";})(),(function f000(){return \"KDh\";})(),(function f000(){return \"DAp\";})(),(function f000(){return \"Br\";})(),(f" ascii
    $s3  = "000(){return \"GGn\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"Ml\";})(),(function f000(){return \"YTp" ascii
    $s4  = " \"MBb\";})(),(function f000(){return \"Um\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"GGn\";})(),(func" ascii
    $s5  = "n \"Nv\";})(),(function f000(){return \"SGs\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"WIj\";})(),(fu" ascii
    $s6  = "on f000(){return \"Go\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"" ascii
    $s7  = "eturn \"PTi\";})(),(function f000(){return \"MJq\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"GGn\";})(" ascii
    $s8  = "\";})(),(function f000(){return \"DYs\";})(),(function f000(){return \"Sv\";})(),(function f000(){return \"Lp\";})(),(function f" ascii
    $s9  = "),(function f000(){return \"SEo\";})(),(function f000(){return \"ZGq\";})(),(function f000(){return \"MJq\";})(),(function f000(" ascii
    $s10 = "eturn \"Br\";})(),(function f000(){return \"MBb\";})(),(function f000(){return \"Mt\";})(),(function f000(){return \"Br\";})(),(" ascii
    $s11 = "f000(){return \"UEg\";})(),(function f000(){return \"Wy\";})(),(function f000(){return \"Oe\";})(),(function f000(){return \"Br" ascii
    $s12 = "ion f000(){return \"GGn\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"PTi\";})(),(function f000(){return " ascii
    $s13 = "r\";})(),(function f000(){return \"DAp\";})(),(function f000(){return \"MOc\";})(),(function f000(){return \"Vj\";})(),(function" ascii
    $s14 = "ion f000(){return \"WIj\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Br\";})(),(function f000(){return " ascii
    $s15 = "})(),(function f000(){return \"DAp\";})(),(function f000(){return \"Um\";})(),(function f000(){return \"DYs\";})(),(function f00" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}