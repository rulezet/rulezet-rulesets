rule _20160921_0466c7255c8e70587363e07e045d3c4a_20160922_41319625a334_4184 {
  meta:
    description = "datamaliciousorder - from files 20160921_0466c7255c8e70587363e07e045d3c4a.js, 20160922_41319625a3342333693d5eefb82a43ce.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "23a4fdb08cf486e569a48a599a4a2c53d91892166b2194b7066e39c535723f8f"
    hash2       = "6cb4a85918ba85e72bd611e7820ea056409f5f25a58a8d15335e282229f10af9"

  strings:
    $s1 = "turn \"GGn\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"Sv\";})(),(function f000(){return \"BMj\";})(),(" ascii
    $s2 = ";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Qa\";})(),(function f000(){return \"MJq\";})(),(function f0" ascii
    $s3 = "return \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return \"Sq\";})()" ascii
    $s4 = "000(){return \"GGn\";})(),(function f000(){return \"Sv\";})(),(function f000(){return \"TKp\";})(),(function f000(){return \"Kw" ascii
    $s5 = "nction f000(){return \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"RLk\";})(),(function f000(){retu" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}