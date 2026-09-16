rule TTP_XOR_QUAD_CurrentVersionRun_3b2c {
  strings:
    $key_3b2c = { 68 43 [2] 4c 4d [2] 67 61 [2] 49 43 [2] 5d 58 [2] 52 42 [2] 4c 5f [2] 4e 5e [2] 55 58 [2] 49 5f [2] 55 70 }

  condition:
    any of them
}