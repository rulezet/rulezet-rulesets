rule _20160921_18cdf3dec8ac4b7697e775bc56ddeba9_20160921_aaf08d1a7081_4542 {
  meta:
    description = "datamaliciousorder - from files 20160921_18cdf3dec8ac4b7697e775bc56ddeba9.js, 20160921_aaf08d1a708106f9bd09a913767a56e1.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1a1aa090c906360f52952b29d512b8c450c7e8c8cff28bc6fded6af15377b37c"
    hash2       = "f9cc4d7e90450eb48dcdeb77c2c486f0893efd6ae609a5f1c7bdf6439f61bda7"

  strings:
    $s1 = "unction f000(){return \"Qz\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"TRc\";})(),(function f000(){retu" ascii
    $s2 = "),(function f000(){return \"UEg\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"Yi\";})(),(function f000()" ascii
    $s3 = "00(){return \"Mu\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"XTn\"" ascii
    $s4 = "})(),(function f000(){return \"Br\";})(),(function f000(){return \"Wy\";})(),(function f000(){return \"Ml\";})(),(function f000(" ascii
    $s5 = "n \"XTn\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"GGn\";})(),(fun" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}