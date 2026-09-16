rule _20160921_731724a743a10eb03d2ee3a92239f369_20160921_9bf90f0e5e3e_5397 {
  meta:
    description = "datamaliciousorder - from files 20160921_731724a743a10eb03d2ee3a92239f369.js, 20160921_9bf90f0e5e3e4249facf6ba81df47434.js, 20160922_37d3775ea966a92be28550dbc5135955.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a7ac1561634dc1fa8b18cc98ccf432021ed2e8b16132f60e88757d855dedeb94"
    hash2       = "7675c3fc0c8c80a2bcfa4fe026386a71ba43352c33e15df8f556bb3e96e97ab5"
    hash3       = "f282b6549f474db716715761c7740ac0669f87438abd864f0e5afe9b148cb29b"

  strings:
    $s1 = "f000(){return \"Ot\";})(),(function f000(){return \"EZu\";})(),(function f000(){return \"Km\";})(),(function f000(){return \"Iq" ascii
    $s2 = "f000(){return \"Lp\";})(),(function f000(){return \"DIa\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Uo" ascii
    $s3 = "tion f000(){return \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"PTi\";})(),(function f000(){return" ascii
    $s4 = "on f000(){return \"GGn\";})(),(function f000(){return \"Nv\";})(),(function f000(){return \"SGs\";})(),(function f000(){return " ascii
    $s5 = "n f000(){return \"Do\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"DIa\";})(),(function f000(){return \"Z" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}