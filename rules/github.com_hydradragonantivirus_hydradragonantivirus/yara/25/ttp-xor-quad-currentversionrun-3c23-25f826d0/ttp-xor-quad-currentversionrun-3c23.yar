rule TTP_XOR_QUAD_CurrentVersionRun_3c23 {
  strings:
    $key_3c23 = { 6f 4c [2] 4b 42 [2] 60 6e [2] 4e 4c [2] 5a 57 [2] 55 4d [2] 4b 50 [2] 49 51 [2] 52 57 [2] 4e 50 [2] 52 7f }

  condition:
    any of them
}