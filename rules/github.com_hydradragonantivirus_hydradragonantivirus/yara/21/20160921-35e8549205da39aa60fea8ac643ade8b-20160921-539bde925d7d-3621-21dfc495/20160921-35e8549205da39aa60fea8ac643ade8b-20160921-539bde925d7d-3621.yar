rule _20160921_35e8549205da39aa60fea8ac643ade8b_20160921_539bde925d7d_3621 {
  meta:
    description = "datamaliciousorder - from files 20160921_35e8549205da39aa60fea8ac643ade8b.js, 20160921_539bde925d7d117e6c387c1b32dd397b.js, 20160921_c745108b7e58564d28687f6e180c98c5.js, 20160921_f0a3d5a403f0d7386ada786b887a464d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fe7319f5e948bc89c8a5f42f117ed0667b1816e94f61d88225df2d217cf74b06"
    hash2       = "9ff498e6534ca553e55771f7eceb4682e639590da978950f1c8683f05f448427"
    hash3       = "933f7e4ee0e09bde34704852e63df99ed6341ecadbe6b7afc2244b8228048418"
    hash4       = "77a7ef76313303139cf36ae2953c6c901152f97fe8ddc013a16c1d4b69e5357c"

  strings:
    $s1 = "ion f000(){return \"Ut\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"RPt\";})(),(function f000(){return " ascii
    $s2 = "00(){return \"OUx\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"RPt\"" ascii
    $s3 = "return \"WIj\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"GGn\";})(" ascii
    $s4 = "rn \"Sq\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"TKp\";})(),(f" ascii
    $s5 = "urn \"Wh\";})(),(function f000(){return \"DIa\";})(),(function f000(){return \"Zj\";})(),(function f000(){return \"MMz\";})(),(f" ascii
    $s6 = "n \"KXg\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"Zj\";})(),(fu" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}