rule _20160921_86391eeb92939f7926213db5cee16e4d_20160921_b71168af39c5_5479 {
  meta:
    description = "datamaliciousorder - from files 20160921_86391eeb92939f7926213db5cee16e4d.js, 20160921_b71168af39c5eec1d403d381eea7ffe1.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1238f360c84929f303678fcd3899297cac43bef18dc5a731b7a6272fde7fe4e6"
    hash2       = "c8811edeb74999e8dd226f7fa9d7963ccfc998904ecb9474d036376253dc6fde"

  strings:
    $s1 = "turn \"Tb\";})(),(function f000(){return \"DYx\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MDb\";})()," ascii
    $s2 = ")(),(function f000(){return \"Qa\";})(),(function f000(){return \"DYx\";})(),(function f000(){return \"DIa\";})(),(function f000" ascii
    $s3 = "ion f000(){return \"ZIi\";})(),(function f000(){return \"PTs\";})(),(function f000(){return \"Iq\";})(),(function f000(){return " ascii
    $s4 = "turn \"Sv\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return \"TKp\";})(),(function f000(){return \"KXg\";})()," ascii
    $s5 = "n f000(){return \"GGn\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return \"ZIi\";})(),(function f000(){return " ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}