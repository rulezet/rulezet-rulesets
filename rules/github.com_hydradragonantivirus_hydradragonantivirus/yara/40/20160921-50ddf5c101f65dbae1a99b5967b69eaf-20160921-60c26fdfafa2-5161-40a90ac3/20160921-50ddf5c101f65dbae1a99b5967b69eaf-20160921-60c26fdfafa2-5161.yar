rule _20160921_50ddf5c101f65dbae1a99b5967b69eaf_20160921_60c26fdfafa2_5161 {
  meta:
    description = "datamaliciousorder - from files 20160921_50ddf5c101f65dbae1a99b5967b69eaf.js, 20160921_60c26fdfafa2666b92246aea46e32175.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4d3df92f56e6b5cba10c96e8cd182f92f3c10aceaabe5a4530b70d3fc5873feb"
    hash2       = "e4cfca41d64bbf1a0959643523d4734a108bc3ecf6147c83f60db030586c6f25"

  strings:
    $s1 = "turn \"Iq\";})(),(function f000(){return \"QDg\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"NYh\";})(),(" ascii
    $s2 = "n f000(){return \"KXg\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"" ascii
    $s3 = "})(),(function f000(){return \"GGn\";})(),(function f000(){return \"KDh\";})(),(function f000(){return \"Oh\";})(),(function f00" ascii
    $s4 = "00(){return \"OUx\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"Kw\"" ascii
    $s5 = "turn \"GGn\";})(),(function f000(){return \"Ut\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"XTn\";})()," ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}