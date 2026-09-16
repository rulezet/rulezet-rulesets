rule TTP_XOR_QUAD_CurrentVersionRun_3623 {
  strings:
    $key_3623 = { 65 4c [2] 41 42 [2] 6a 6e [2] 44 4c [2] 50 57 [2] 5f 4d [2] 41 50 [2] 43 51 [2] 58 57 [2] 44 50 [2] 58 7f }

  condition:
    any of them
}