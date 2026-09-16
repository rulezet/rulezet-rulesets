rule _20160921_0ff0e00bae268a8e48b8e6fc134c3779_20160921_5496891f48e4_4384 {
  meta:
    description = "datamaliciousorder - from files 20160921_0ff0e00bae268a8e48b8e6fc134c3779.js, 20160921_5496891f48e427ad533fc8e112e9bb4f.js, 20160922_6bc7e7cb9bbab9434a7d6dc7718c610f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4f9f30b45066ff23899a854b2ef766240b2becea05223ad11c6bf5cde97c3048"
    hash2       = "fb85e1d59ed8f9cee344ab5ab95f651cb8fb1ee7ec35d0a88f8f41279a3d17a6"
    hash3       = "1ce9e0dc49979ee9e18675311cb94170c53d3836b9d2c99b0e6d51f9cc27fe15"

  strings:
    $s1 = "(),(function f000(){return \"RPt\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"Zj\";})(),(function f000(" ascii
    $s2 = "Db\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return \"DYx\";})(),(functi" ascii
    $s3 = "on f000(){return \"MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Nv\";})(),(function f000(){return " ascii
    $s4 = "nction f000(){return \"Sv\";})(),(function f000(){return \"Tb\";})(),(function f000(){return \"Oe\";})(),(function f000(){return" ascii
    $s5 = "return \"Oh\";})(),(function f000(){return \"YTp\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"GGn\";})()" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}