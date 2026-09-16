rule TTP_XOR_QUAD_CurrentVersionRun_23a2 {
  strings:
    $key_23a2 = { 70 cd [2] 54 c3 [2] 7f ef [2] 51 cd [2] 45 d6 [2] 4a cc [2] 54 d1 [2] 56 d0 [2] 4d d6 [2] 51 d1 [2] 4d fe }

  condition:
    any of them
}