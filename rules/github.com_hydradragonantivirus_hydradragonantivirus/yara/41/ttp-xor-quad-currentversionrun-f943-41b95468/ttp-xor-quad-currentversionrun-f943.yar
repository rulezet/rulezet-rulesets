rule TTP_XOR_QUAD_CurrentVersionRun_f943 {
  strings:
    $key_f943 = { aa 2c [2] 8e 22 [2] a5 0e [2] 8b 2c [2] 9f 37 [2] 90 2d [2] 8e 30 [2] 8c 31 [2] 97 37 [2] 8b 30 [2] 97 1f }

  condition:
    any of them
}