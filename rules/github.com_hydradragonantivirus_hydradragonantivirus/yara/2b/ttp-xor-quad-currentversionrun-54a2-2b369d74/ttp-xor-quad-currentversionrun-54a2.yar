rule TTP_XOR_QUAD_CurrentVersionRun_54a2 {
  strings:
    $key_54a2 = { 07 cd [2] 23 c3 [2] 08 ef [2] 26 cd [2] 32 d6 [2] 3d cc [2] 23 d1 [2] 21 d0 [2] 3a d6 [2] 26 d1 [2] 3a fe }

  condition:
    any of them
}