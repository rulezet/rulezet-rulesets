rule TTP_XOR_QUAD_CurrentVersionRun_e573 {
  strings:
    $key_e573 = { b6 1c [2] 92 12 [2] b9 3e [2] 97 1c [2] 83 07 [2] 8c 1d [2] 92 00 [2] 90 01 [2] 8b 07 [2] 97 00 [2] 8b 2f }

  condition:
    any of them
}