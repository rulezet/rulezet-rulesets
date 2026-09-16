rule TTP_XOR_QUAD_CurrentVersionRun_25a2 {
  strings:
    $key_25a2 = { 76 cd [2] 52 c3 [2] 79 ef [2] 57 cd [2] 43 d6 [2] 4c cc [2] 52 d1 [2] 50 d0 [2] 4b d6 [2] 57 d1 [2] 4b fe }

  condition:
    any of them
}