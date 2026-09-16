rule _20160921_35e8549205da39aa60fea8ac643ade8b_20160921_5e3ac68b2242_4903 {
  meta:
    description = "datamaliciousorder - from files 20160921_35e8549205da39aa60fea8ac643ade8b.js, 20160921_5e3ac68b2242250176f3300039d176f6.js, 20160921_c745108b7e58564d28687f6e180c98c5.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fe7319f5e948bc89c8a5f42f117ed0667b1816e94f61d88225df2d217cf74b06"
    hash2       = "89b3eb7dc82702c0fd809112cd45d647e28906b665dcfd9718254fadc25580e9"
    hash3       = "933f7e4ee0e09bde34704852e63df99ed6341ecadbe6b7afc2244b8228048418"

  strings:
    $s1 = "unction f000(){return \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"ZFe\";})(),(function f000(){ret" ascii
    $s2 = "nction f000(){return \"Yi\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"PTs\";})(),(function f000(){retu" ascii
    $s3 = "n f000(){return \"RPt\";})(),(function f000(){return \"QDg\";})(),(function f000(){return \"Yv\";})(),(function f000(){return \"" ascii
    $s4 = "v\";})(),(function f000(){return \"Sq\";})(),(function f000(){return \"Zj\";})(),(function f000(){return \"MMz\";})(),(function " ascii
    $s5 = "n f000(){return \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"HJm\";})(),(function f000(){return \"" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}