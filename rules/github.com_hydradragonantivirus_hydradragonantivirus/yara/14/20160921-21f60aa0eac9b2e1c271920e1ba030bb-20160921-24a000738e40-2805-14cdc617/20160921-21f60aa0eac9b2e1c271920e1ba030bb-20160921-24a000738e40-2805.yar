rule _20160921_21f60aa0eac9b2e1c271920e1ba030bb_20160921_24a000738e40_2805 {
  meta:
    description = "datamaliciousorder - from files 20160921_21f60aa0eac9b2e1c271920e1ba030bb.js, 20160921_24a000738e40009c8bea0a81a0c09cf4.js, 20160921_67c50b9dab5bb43a7f01552ab820f46c.js, 20160921_8471da3d602dedb9a4749d6e2c757b47.js, 20160921_9bf90f0e5e3e4249facf6ba81df47434.js, 20160922_37d3775ea966a92be28550dbc5135955.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d62e554404acfef03995a5bdd7d29935f7247fd9707d5ea364fac80fddc940f7"
    hash2       = "f61bde20fd51cb3330f21d75680b7197049050166838d3ae36cae4b7521bfd50"
    hash3       = "95b498a0f19ae8b7e9793e4cb9042b95bb6ba62738825d4cc0684c4bbb8a3d9d"
    hash4       = "98a5a561c128a716a07f6503ae8144cb9404c06eb1a2796af84924653c81967c"
    hash5       = "7675c3fc0c8c80a2bcfa4fe026386a71ba43352c33e15df8f556bb3e96e97ab5"
    hash6       = "f282b6549f474db716715761c7740ac0669f87438abd864f0e5afe9b148cb29b"

  strings:
    $s1 = "eturn \"TKl\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"Sv\";})(),(function f000(){return \"TKp\";})()" ascii
    $s2 = "on f000(){return \"Kw\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"RLk\";})(),(function f000(){return " ascii
    $s3 = "\"RLk\";})(),(function f000(){return \"Mt\";})(),(function f000(){return \"OMd\";})(),(function f000(){return \"GGn\";})(),(func" ascii
    $s4 = ")(),(function f000(){return \"MDb\";})(),(function f000(){return \"Qa\";})(),(function f000(){return \"MJq\";})(),(function f000" ascii
    $s5 = "rn \"DNa\";})(),(function f000(){return \"Wy\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"GGn\";})(),(fu" ascii
    $s6 = "urn \"MDb\";})(),(function f000(){return \"HJm\";})(),(function f000(){return \"RLk\";})(),(function f000(){return \"TKp\";})()," ascii
    $s7 = "{return \"Sq\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"PTi\";})(),(function f000(){return \"ZFe\";})" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}