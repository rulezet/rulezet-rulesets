rule _20160921_4ad5ed78dc05b02005f65ab785b9c74a_20160921_e59567324a54_5093 {
  meta:
    description = "datamaliciousorder - from files 20160921_4ad5ed78dc05b02005f65ab785b9c74a.js, 20160921_e59567324a545ca23bf9e3ba990b6526.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7e5f9d362688f19111d3dbdf393d51e133fcc63eb7db27536cb31d1205ccc9e3"
    hash2       = "ce1d8f63fc8c7b91e97f36fa89b000d70fc284d08682ca3a91ee6c2a4e6e2c72"

  strings:
    $s1 = "f000(){return \"Qa\";})(),(function f000(){return \"MBb\";})(),(function f000(){return \"BMj\";})(),(function f000(){return \"MD" ascii
    $s2 = "function f000(){return \"GGn\";})(),(function f000(){return \"IAa\";})(),(function f000(){return \"IPu\";})(),(function f000(){r" ascii
    $s3 = "urn \"Yv\";})(),(function f000(){return \"Sv\";})(),(function f000(){return \"NBs\";})(),(function f000(){return \"MDb\";})(),(f" ascii
    $s4 = "0(){return \"KDh\";})(),(function f000(){return \"MJq\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MDb" ascii
    $s5 = "})(),(function f000(){return \"Go\";})(),(function f000(){return \"Iq\";})(),(function f000(){return \"MDb\";})(),(function f000" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}