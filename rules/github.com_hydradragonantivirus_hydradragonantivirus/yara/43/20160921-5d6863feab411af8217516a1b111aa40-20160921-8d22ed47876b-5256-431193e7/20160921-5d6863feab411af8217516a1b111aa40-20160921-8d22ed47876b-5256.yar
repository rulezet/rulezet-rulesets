rule _20160921_5d6863feab411af8217516a1b111aa40_20160921_8d22ed47876b_5256 {
  meta:
    description = "datamaliciousorder - from files 20160921_5d6863feab411af8217516a1b111aa40.js, 20160921_8d22ed47876b303a1415a88483556238.js, 20160921_b71168af39c5eec1d403d381eea7ffe1.js, 20160921_c1184914bc801e9725b7f52a13eaa885.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0dbd74ce266dbd495fb6fc7810ec67099f628d975c524a9190f91ccc4bf433bb"
    hash2       = "666a3f8cd9a533a20e260aad6bcb18265aad030f6f978c4cc3c9da557262f1ae"
    hash3       = "c8811edeb74999e8dd226f7fa9d7963ccfc998904ecb9474d036376253dc6fde"
    hash4       = "b978f77ee1e2384ffdbb55f48f7d8fb0a9b642fc4b2f38d86c68e4f6357d5153"

  strings:
    $s1 = "tion f000(){return \"Nv\";})(),(function f000(){return \"Nv\";})(),(function f000(){return \"SGs\";})(),(function f000(){return " ascii
    $s2 = "NBs\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"Go\";})(),(functio" ascii
    $s3 = "ion f000(){return \"GGn\";})(),(function f000(){return \"DYs\";})(),(function f000(){return \"KDh\";})(),(function f000(){return" ascii
    $s4 = "eturn \"KDh\";})(),(function f000(){return \"NYh\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MDb\";})(" ascii
    $s5 = "eturn \"HJm\";})(),(function f000(){return \"Rh\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"QDg\";})()" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}