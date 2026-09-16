rule TTP_XOR_QUAD_CurrentVersionRun_364d {
  strings:
    $key_364d = { 65 22 [2] 41 2c [2] 6a 00 [2] 44 22 [2] 50 39 [2] 5f 23 [2] 41 3e [2] 43 3f [2] 58 39 [2] 44 3e [2] 58 11 }

  condition:
    any of them
}