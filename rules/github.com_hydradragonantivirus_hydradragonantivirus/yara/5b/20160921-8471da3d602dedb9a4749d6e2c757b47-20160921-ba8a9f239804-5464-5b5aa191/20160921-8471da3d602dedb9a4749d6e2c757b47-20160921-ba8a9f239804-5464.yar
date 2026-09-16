rule _20160921_8471da3d602dedb9a4749d6e2c757b47_20160921_ba8a9f239804_5464 {
  meta:
    description = "datamaliciousorder - from files 20160921_8471da3d602dedb9a4749d6e2c757b47.js, 20160921_ba8a9f239804499b5d1d2a06a862c1ca.js, 20160921_cdeac57ac549120611856c7af0c490f6.js, 20160921_ee1327bdf201e62d1f7ae5482cabbd90.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "98a5a561c128a716a07f6503ae8144cb9404c06eb1a2796af84924653c81967c"
    hash2       = "4ab28724a794acc5764f2e51f93d2b91ef9513b43e4cb9b0d10bad2710c2e6d7"
    hash3       = "53694193718c2cb2f90fada2d6a11f07ab2c3f8451a0f41ae580b87a142e212e"
    hash4       = "91500ac726f9d2548dffc99162aeece9863dc7b928106d27a769e6bbf9439f81"

  strings:
    $s1 = "),(function f000(){return \"QDg\";})(),(function f000(){return \"UEg\";})(),(function f000(){return \"OUx\";})(),(function f000(" ascii
    $s2 = "n \"Mu\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"KXg\";})(),(fu" ascii
    $s3 = "{return \"OUx\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"Qz\";})(" ascii
    $s4 = "rn \"Yi\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"WIj\";})(),(f" ascii
    $s5 = "\"OUx\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"GGn\";})(),(fun" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}