rule _20160921_13a6ecf7a8d1b8c1e6c88d1f386d0fdc_20160921_cebdb99ce2e5_4439 {
  meta:
    description = "datamaliciousorder - from files 20160921_13a6ecf7a8d1b8c1e6c88d1f386d0fdc.js, 20160921_cebdb99ce2e54d24acef5b8ee0096562.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a1db38abaeb5bf0ea6f5b5ff0f4a9eedd9ce90cd62e2966ce8936e8e8fbc2905"
    hash2       = "87071d18d308dc7717dabe03dc0d11efe7ee7231e95d9fca71e480f5f2430f7d"

  strings:
    $s1 = "rn \"GGn\";})(),(function f000(){return \"SEo\";})(),(function f000(){return \"Km\";})(),(function f000(){return \"GGn\";})(),(f" ascii
    $s2 = ")(),(function f000(){return \"MBb\";})(),(function f000(){return \"ZGq\";})(),(function f000(){return \"Wb\";})(),(function f000" ascii
    $s3 = "000(){return \"GGn\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Yi" ascii
    $s4 = "n \"Wy\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"WIj\";})(),(fu" ascii
    $s5 = ")(),(function f000(){return \"HJm\";})(),(function f000(){return \"Tn\";})(),(function f000(){return \"XTn\";})(),(function f000" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}