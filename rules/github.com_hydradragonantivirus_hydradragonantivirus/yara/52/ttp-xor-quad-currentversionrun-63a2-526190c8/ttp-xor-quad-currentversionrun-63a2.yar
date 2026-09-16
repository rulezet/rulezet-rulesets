rule TTP_XOR_QUAD_CurrentVersionRun_63a2 {
  strings:
    $key_63a2 = { 30 cd [2] 14 c3 [2] 3f ef [2] 11 cd [2] 05 d6 [2] 0a cc [2] 14 d1 [2] 16 d0 [2] 0d d6 [2] 11 d1 [2] 0d fe }

  condition:
    any of them
}