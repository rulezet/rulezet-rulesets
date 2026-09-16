rule _20160921_2b1783136e2caa674fa83100212e0871_20160921_6167c3d38189_3565 {
  meta:
    description = "datamaliciousorder - from files 20160921_2b1783136e2caa674fa83100212e0871.js, 20160921_6167c3d38189e7b1134d16083ffbd574.js, 20160921_8ed14dc63f5bac37baa70510a94f2915.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4f4f696f319827ea3bc8e0b927eddbd7a588f390148cae3276f1573d816d8889"
    hash2       = "02d7a73acd6af9940f585a0e89095467489ba0ac094eb93050d43dab5745e5bd"
    hash3       = "e01d4cea60f1c16b2fc3a28a98b5ad4d421b0c4e8e5f757805e98a1436a9fadd"

  strings:
    $s1 = " f000(){return \"TRc\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"" ascii
    $s2 = " \"KXg\";})(),(function f000(){return \"DNa\";})(),(function f000(){return \"Zj\";})(),(function f000(){return \"Do\";})(),(func" ascii
    $s3 = "){return \"Go\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"Iq\";})(),(function f000(){return \"PTs\";})(" ascii
    $s4 = "turn \"Kw\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"PTs\";})()," ascii
    $s5 = "f000(){return \"Kw\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"PT" ascii
    $s6 = "rn \"PTs\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"Zj\";})(),(function f000(){return \"Do\";})(),(fun" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}