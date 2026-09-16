rule TTP_XOR_QUAD_CurrentVersionRun_0c2c {
  strings:
    $key_0c2c = { 5f 43 [2] 7b 4d [2] 50 61 [2] 7e 43 [2] 6a 58 [2] 65 42 [2] 7b 5f [2] 79 5e [2] 62 58 [2] 7e 5f [2] 62 70 }

  condition:
    any of them
}