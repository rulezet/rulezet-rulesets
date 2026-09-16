rule _20160921_5541f4e80ad2d4f163ebcd0e8c899e59_20160921_7ffe38e0972c_3790 {
  meta:
    description = "datamaliciousorder - from files 20160921_5541f4e80ad2d4f163ebcd0e8c899e59.js, 20160921_7ffe38e0972c323071684bfa98cafbdf.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "615edf37483855ab2b78dd87e38795245913e5fc6efc9bc47d9e698132792739"
    hash2       = "4bc751383d4c72f88b3f59d9fde1f38f09a81b77ee4df0498bec1df7cd088bc7"

  strings:
    $s1 = "{return \"Nx\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"Yi\";})()" ascii
    $s2 = "urn \"ZFe\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"WIj\";})(),(" ascii
    $s3 = "n f000(){return \"Vj\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"" ascii
    $s4 = "function f000(){return \"KXg\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return \"Vu\";})(),(function f000(){re" ascii
    $s5 = "Dh\";})(),(function f000(){return \"SEo\";})(),(function f000(){return \"NBs\";})(),(function f000(){return \"Yi\";})(),(functio" ascii
    $s6 = "Iq\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return \"Ml\";})(),(function f000(){return \"Nv\";})(),(function" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}