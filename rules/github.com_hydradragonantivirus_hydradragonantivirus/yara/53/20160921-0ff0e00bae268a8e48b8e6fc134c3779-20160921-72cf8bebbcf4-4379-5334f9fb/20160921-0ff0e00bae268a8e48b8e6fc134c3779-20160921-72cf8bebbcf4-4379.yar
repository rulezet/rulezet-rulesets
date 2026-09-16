rule _20160921_0ff0e00bae268a8e48b8e6fc134c3779_20160921_72cf8bebbcf4_4379 {
  meta:
    description = "datamaliciousorder - from files 20160921_0ff0e00bae268a8e48b8e6fc134c3779.js, 20160921_72cf8bebbcf48b45894fe7d7b3327a58.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4f9f30b45066ff23899a854b2ef766240b2becea05223ad11c6bf5cde97c3048"
    hash2       = "004799df77a97e1e1816f6a4a1acf9bec5dfd13ae07613832796a6c9ef0cc578"

  strings:
    $s1 = "GGn\";})(),(function f000(){return \"Rh\";})(),(function f000(){return \"DYx\";})(),(function f000(){return \"TKp\";})(),(functi" ascii
    $s2 = "(){return \"Wy\";})(),(function f000(){return \"QDg\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"DIa\";}" ascii
    $s3 = "ction f000(){return \"Oe\";})(),(function f000(){return \"Zj\";})(),(function f000(){return \"KZr\";})(),(function f000(){return" ascii
    $s4 = "n f000(){return \"DYx\";})(),(function f000(){return \"TKp\";})(),(function f000(){return \"GGn\";})(),(function f000(){return " ascii
    $s5 = " \"Ml\";})(),(function f000(){return \"Tb\";})(),(function f000(){return \"SGs\";})(),(function f000(){return \"Iq\";})(),(funct" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}