rule _20160921_3e5e21af311d364f73107419b54e74e3_20160921_5e3ac68b2242_5020 {
  meta:
    description = "datamaliciousorder - from files 20160921_3e5e21af311d364f73107419b54e74e3.js, 20160921_5e3ac68b2242250176f3300039d176f6.js, 20160921_86391eeb92939f7926213db5cee16e4d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8b6cb861af32c3db5ac97103bfe3b904e62a9eee40ed51764665b556005b9510"
    hash2       = "89b3eb7dc82702c0fd809112cd45d647e28906b665dcfd9718254fadc25580e9"
    hash3       = "1238f360c84929f303678fcd3899297cac43bef18dc5a731b7a6272fde7fe4e6"

  strings:
    $s1 = "Bs\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"QDg\";})(),(function f000(){return \"DYs\";})(),(functi" ascii
    $s2 = "turn \"Qp\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"DYs\";})(),(function f000(){return \"Yv\";})(),(" ascii
    $s3 = "nction f000(){return \"KXg\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"SEo\";})(),(function f000(){ret" ascii
    $s4 = ";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Qp\";})(),(function f00" ascii
    $s5 = "\"GGn\";})(),(function f000(){return \"PLy\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"KXg\";})(),(fun" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}