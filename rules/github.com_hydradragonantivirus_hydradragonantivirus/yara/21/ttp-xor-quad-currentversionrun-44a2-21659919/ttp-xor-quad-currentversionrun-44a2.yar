rule TTP_XOR_QUAD_CurrentVersionRun_44a2 {
  strings:
    $key_44a2 = { 17 cd [2] 33 c3 [2] 18 ef [2] 36 cd [2] 22 d6 [2] 2d cc [2] 33 d1 [2] 31 d0 [2] 2a d6 [2] 36 d1 [2] 2a fe }

  condition:
    any of them
}