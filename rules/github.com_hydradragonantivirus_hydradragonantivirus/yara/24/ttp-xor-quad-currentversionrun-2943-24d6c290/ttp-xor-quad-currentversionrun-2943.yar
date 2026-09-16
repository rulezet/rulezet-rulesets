rule TTP_XOR_QUAD_CurrentVersionRun_2943 {
  strings:
    $key_2943 = { 7a 2c [2] 5e 22 [2] 75 0e [2] 5b 2c [2] 4f 37 [2] 40 2d [2] 5e 30 [2] 5c 31 [2] 47 37 [2] 5b 30 [2] 47 1f }

  condition:
    any of them
}