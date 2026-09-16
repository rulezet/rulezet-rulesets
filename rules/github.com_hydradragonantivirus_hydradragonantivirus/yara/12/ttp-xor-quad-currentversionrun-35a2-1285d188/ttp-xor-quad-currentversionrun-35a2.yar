rule TTP_XOR_QUAD_CurrentVersionRun_35a2 {
  strings:
    $key_35a2 = { 66 cd [2] 42 c3 [2] 69 ef [2] 47 cd [2] 53 d6 [2] 5c cc [2] 42 d1 [2] 40 d0 [2] 5b d6 [2] 47 d1 [2] 5b fe }

  condition:
    any of them
}