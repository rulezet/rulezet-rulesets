rule TTP_XOR_QUAD_CurrentVersionRun_2d2c {
  strings:
    $key_2d2c = { 7e 43 [2] 5a 4d [2] 71 61 [2] 5f 43 [2] 4b 58 [2] 44 42 [2] 5a 5f [2] 58 5e [2] 43 58 [2] 5f 5f [2] 43 70 }

  condition:
    any of them
}