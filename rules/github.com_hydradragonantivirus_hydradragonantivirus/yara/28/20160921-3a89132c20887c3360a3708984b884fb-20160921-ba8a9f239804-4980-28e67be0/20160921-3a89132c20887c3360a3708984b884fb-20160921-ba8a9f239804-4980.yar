rule _20160921_3a89132c20887c3360a3708984b884fb_20160921_ba8a9f239804_4980 {
  meta:
    description = "datamaliciousorder - from files 20160921_3a89132c20887c3360a3708984b884fb.js, 20160921_ba8a9f239804499b5d1d2a06a862c1ca.js, 20160921_ee1327bdf201e62d1f7ae5482cabbd90.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9687ad9b2ded14e00c5b17393de82acd451266863fb217fc6647e1add112f2fd"
    hash2       = "4ab28724a794acc5764f2e51f93d2b91ef9513b43e4cb9b0d10bad2710c2e6d7"
    hash3       = "91500ac726f9d2548dffc99162aeece9863dc7b928106d27a769e6bbf9439f81"

  strings:
    $s1 = "OUx\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"Vu\";})(),(functio" ascii
    $s2 = "f000(){return \"Mu\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"Qz" ascii
    $s3 = "GGn\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"RPt\";})(),(functio" ascii
    $s4 = "{return \"KXg\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"Zj\";})()" ascii
    $s5 = "),(function f000(){return \"Kw\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"TRc\";})(),(function f000(){" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}