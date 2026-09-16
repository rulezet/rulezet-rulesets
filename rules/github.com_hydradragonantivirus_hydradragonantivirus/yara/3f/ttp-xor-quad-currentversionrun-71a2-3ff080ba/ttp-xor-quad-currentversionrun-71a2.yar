rule TTP_XOR_QUAD_CurrentVersionRun_71a2 {
  strings:
    $key_71a2 = { 22 cd [2] 06 c3 [2] 2d ef [2] 03 cd [2] 17 d6 [2] 18 cc [2] 06 d1 [2] 04 d0 [2] 1f d6 [2] 03 d1 [2] 1f fe }

  condition:
    any of them
}