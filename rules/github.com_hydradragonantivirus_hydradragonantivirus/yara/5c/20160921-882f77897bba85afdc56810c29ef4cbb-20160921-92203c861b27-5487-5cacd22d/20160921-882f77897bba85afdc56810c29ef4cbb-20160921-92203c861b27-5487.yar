rule _20160921_882f77897bba85afdc56810c29ef4cbb_20160921_92203c861b27_5487 {
  meta:
    description = "datamaliciousorder - from files 20160921_882f77897bba85afdc56810c29ef4cbb.js, 20160921_92203c861b27f106aadc39fdc2b4c6b7.js, 20160921_d999dcba53f56b5a9c1abcc062fbeb80.js, 20160921_ebd0ee36b6a55e4cbf431d8fa9a2aea3.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9e1a86c6dc71a5b10659658c07a01bb1541887750ecf88ab56997c7dbc2d180c"
    hash2       = "307c62eb5d0e72645486ed8ab490a017889f28cb40d74f607fae031e9ef250fb"
    hash3       = "3bf893eeec71a95167368eb58abcbfe36362779b946b3e0d29c9032ec427ebd4"
    hash4       = "f2f666db493211ee6edb824e429f601fccdbf25cd3cc08bc16ad31fdf23c4636"

  strings:
    $s1 = "00(){return \"YTp\";})(),(function f000(){return \"Mt\";})(),(function f000(){return \"UEg\";})(),(function f000(){return \"Wy\"" ascii
    $s2 = "unction f000(){return \"Yz\";})(),(function f000(){return \"Wy\";})(),(function f000(){return \"Oe\";})(),(function f000(){retur" ascii
    $s3 = "return \"DIa\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Uo\";})(),(function f000(){return \"MBb\";})(" ascii
    $s4 = "urn \"Ml\";})(),(function f000(){return \"Tn\";})(),(function f000(){return \"Oe\";})(),(function f000(){return \"Yz\";})(),(fun" ascii
    $s5 = "on f000(){return \"Oe\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"QDg\";})(),(function f000(){return " ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}