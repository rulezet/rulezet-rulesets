rule TTP_XOR_QUAD_CurrentVersionRun_3e2c {
  strings:
    $key_3e2c = { 6d 43 [2] 49 4d [2] 62 61 [2] 4c 43 [2] 58 58 [2] 57 42 [2] 49 5f [2] 4b 5e [2] 50 58 [2] 4c 5f [2] 50 70 }

  condition:
    any of them
}