rule TTP_XOR_QUAD_CurrentVersionRun_45a2 {
  strings:
    $key_45a2 = { 16 cd [2] 32 c3 [2] 19 ef [2] 37 cd [2] 23 d6 [2] 2c cc [2] 32 d1 [2] 30 d0 [2] 2b d6 [2] 37 d1 [2] 2b fe }

  condition:
    any of them
}