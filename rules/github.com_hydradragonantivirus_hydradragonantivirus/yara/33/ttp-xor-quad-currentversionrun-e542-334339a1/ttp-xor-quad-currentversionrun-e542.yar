rule TTP_XOR_QUAD_CurrentVersionRun_e542 {
  strings:
    $key_e542 = { b6 2d [2] 92 23 [2] b9 0f [2] 97 2d [2] 83 36 [2] 8c 2c [2] 92 31 [2] 90 30 [2] 8b 36 [2] 97 31 [2] 8b 1e }

  condition:
    any of them
}