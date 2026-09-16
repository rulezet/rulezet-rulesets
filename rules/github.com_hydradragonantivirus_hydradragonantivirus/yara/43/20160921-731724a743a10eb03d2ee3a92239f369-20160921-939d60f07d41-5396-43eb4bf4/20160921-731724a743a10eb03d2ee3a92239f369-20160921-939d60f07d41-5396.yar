rule _20160921_731724a743a10eb03d2ee3a92239f369_20160921_939d60f07d41_5396 {
  meta:
    description = "datamaliciousorder - from files 20160921_731724a743a10eb03d2ee3a92239f369.js, 20160921_939d60f07d4171a5bae4c0b4ca33f3d9.js, 20160921_9bf90f0e5e3e4249facf6ba81df47434.js, 20160922_37d3775ea966a92be28550dbc5135955.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a7ac1561634dc1fa8b18cc98ccf432021ed2e8b16132f60e88757d855dedeb94"
    hash2       = "c23bfef986de7a073bbcd781aa45ad15287fb2c448d110b92a01e652f22ff335"
    hash3       = "7675c3fc0c8c80a2bcfa4fe026386a71ba43352c33e15df8f556bb3e96e97ab5"
    hash4       = "f282b6549f474db716715761c7740ac0669f87438abd864f0e5afe9b148cb29b"

  strings:
    $s1 = "rn \"Oe\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"UOt\";})(),(function f000(){return \"GGn\";})(),(f" ascii
    $s2 = "function f000(){return \"BQb\";})(),(function f000(){return \"Oe\";})(),(function f000(){return \"GGn\";})(),(function f000(){re" ascii
    $s3 = "})(),(function f000(){return \"Wy\";})(),(function f000(){return \"Yz\";})(),(function f000(){return \"Wy\";})(),(function f000(" ascii
    $s4 = "(){return \"TKl\";})(),(function f000(){return \"Ml\";})(),(function f000(){return \"Tn\";})(),(function f000(){return \"Oe\";})" ascii
    $s5 = "tion f000(){return \"Yz\";})(),(function f000(){return \"YTp\";})(),(function f000(){return \"Mt\";})(),(function f000(){return " ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}