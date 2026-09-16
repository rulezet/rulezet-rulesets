rule _20160921_09574acd8f408e24693e435b8c769e04_20160921_ba8a9f239804_4309 {
  meta:
    description = "datamaliciousorder - from files 20160921_09574acd8f408e24693e435b8c769e04.js, 20160921_ba8a9f239804499b5d1d2a06a862c1ca.js, 20160921_cdeac57ac549120611856c7af0c490f6.js, 20160921_d7492227e681b1689bfc5442a91a169e.js, 20160921_ee1327bdf201e62d1f7ae5482cabbd90.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "502f3f7db781b4ecddec50bed418f60953253591a8d3d5ab1aa2cc3352cd6821"
    hash2       = "4ab28724a794acc5764f2e51f93d2b91ef9513b43e4cb9b0d10bad2710c2e6d7"
    hash3       = "53694193718c2cb2f90fada2d6a11f07ab2c3f8451a0f41ae580b87a142e212e"
    hash4       = "63aa129680edf69c72e8f077be5e8562f041fa0b0c7e63a8a9b219c23749b135"
    hash5       = "91500ac726f9d2548dffc99162aeece9863dc7b928106d27a769e6bbf9439f81"

  strings:
    $s1 = "){return \"XTn\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"Qz\";})" ascii
    $s2 = "nction f000(){return \"TRc\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Qp\";})(),(function f000(){retu" ascii
    $s3 = "nction f000(){return \"XTn\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"TKl\";})(),(function f000(){ret" ascii
    $s4 = "Mu\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"GGn\";})(),(functio" ascii
    $s5 = "tion f000(){return \"TRc\";})(),(function f000(){return \"Mu\";})(),(function f000(){return \"RPt\";})(),(function f000(){return" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}