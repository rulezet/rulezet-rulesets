rule TTP_XOR_QUAD_CurrentVersionRun_e523 {
  strings:
    $key_e523 = { b6 4c [2] 92 42 [2] b9 6e [2] 97 4c [2] 83 57 [2] 8c 4d [2] 92 50 [2] 90 51 [2] 8b 57 [2] 97 50 [2] 8b 7f }

  condition:
    any of them
}