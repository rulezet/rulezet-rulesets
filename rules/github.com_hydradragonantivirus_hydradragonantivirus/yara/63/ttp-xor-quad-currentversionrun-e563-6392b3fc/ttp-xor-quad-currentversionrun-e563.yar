rule TTP_XOR_QUAD_CurrentVersionRun_e563 {
  strings:
    $key_e563 = { b6 0c [2] 92 02 [2] b9 2e [2] 97 0c [2] 83 17 [2] 8c 0d [2] 92 10 [2] 90 11 [2] 8b 17 [2] 97 10 [2] 8b 3f }

  condition:
    any of them
}