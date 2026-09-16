rule TTP_XOR_QUAD_CurrentVersionRun_53a2 {
  strings:
    $key_53a2 = { 00 cd [2] 24 c3 [2] 0f ef [2] 21 cd [2] 35 d6 [2] 3a cc [2] 24 d1 [2] 26 d0 [2] 3d d6 [2] 21 d1 [2] 3d fe }

  condition:
    any of them
}