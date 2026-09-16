rule _20160921_60c26fdfafa2666b92246aea46e32175_20160921_ea3000546b29_3843 {
  meta:
    description = "datamaliciousorder - from files 20160921_60c26fdfafa2666b92246aea46e32175.js, 20160921_ea3000546b29aee563be9d58318d1857.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e4cfca41d64bbf1a0959643523d4734a108bc3ecf6147c83f60db030586c6f25"
    hash2       = "eb46ac22bc2e86a5bacf6fbfffe3a746600369a5d28c84d095b1269bcdfe9cc6"

  strings:
    $s1 = "){return \"ZIi\";})(),(function f000(){return \"Oe\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"WIj\";}" ascii
    $s2 = "ction f000(){return \"GGn\";})(),(function f000(){return \"Sj\";})(),(function f000(){return \"SGs\";})(),(function f000(){retur" ascii
    $s3 = "tion f000(){return \"Ut\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"KXg\";})(),(function f000(){return" ascii
    $s4 = "000(){return \"WIj\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Nv\";})(),(function f000(){return \"Vu" ascii
    $s5 = "unction f000(){return \"Km\";})(),(function f000(){return \"Ml\";})(),(function f000(){return \"Tn\";})(),(function f000(){retur" ascii
    $s6 = "return \"MJq\";})(),(function f000(){return \"QDg\";})(),(function f000(){return \"DIa\";})(),(function f000(){return \"GGn\";})" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}