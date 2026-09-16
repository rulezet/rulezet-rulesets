rule TTP_XOR_QUAD_CurrentVersionRun_15a2 {
  strings:
    $key_15a2 = { 46 cd [2] 62 c3 [2] 49 ef [2] 67 cd [2] 73 d6 [2] 7c cc [2] 62 d1 [2] 60 d0 [2] 7b d6 [2] 67 d1 [2] 7b fe }

  condition:
    any of them
}