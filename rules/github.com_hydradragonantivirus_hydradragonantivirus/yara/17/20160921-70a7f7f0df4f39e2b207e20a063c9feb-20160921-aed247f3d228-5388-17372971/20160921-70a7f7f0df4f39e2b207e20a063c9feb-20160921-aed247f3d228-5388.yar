rule _20160921_70a7f7f0df4f39e2b207e20a063c9feb_20160921_aed247f3d228_5388 {
  meta:
    description = "datamaliciousorder - from files 20160921_70a7f7f0df4f39e2b207e20a063c9feb.js, 20160921_aed247f3d2282ef44bd04021d1a47ef8.js, 20160921_b9bf4d00098353791f6752da8f2fba0d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a31a1dde0b2d683e4ae7fa3037209a425605b8e0a49f1607ea1dd02a4eaed267"
    hash2       = "163159bd2bdf088e94bb401b56d374651d890ca6420982f4654021ab58ff2e2d"
    hash3       = "fb6ed05e313f10d63719b3d6465378a522453c08ee11e88d9852f5e4ba4f69fa"

  strings:
    $s1 = "(function f000(){return \"Nv\";})(),(function f000(){return \"MBb\";})(),(function f000(){return \"DYx\";})(),(function f000(){r" ascii
    $s2 = "000(){return \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"DNa\";})(),(function f000(){return \"Tn" ascii
    $s3 = "{return \"Uo\";})(),(function f000(){return \"EZu\";})(),(function f000(){return \"DIa\";})(),(function f000(){return \"MMz\";})" ascii
    $s4 = "on f000(){return \"ZIi\";})(),(function f000(){return \"Oe\";})(),(function f000(){return \"DIa\";})(),(function f000(){return " ascii
    $s5 = "(){return \"DYx\";})(),(function f000(){return \"MJq\";})(),(function f000(){return \"QDg\";})(),(function f000(){return \"Oh\";" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}