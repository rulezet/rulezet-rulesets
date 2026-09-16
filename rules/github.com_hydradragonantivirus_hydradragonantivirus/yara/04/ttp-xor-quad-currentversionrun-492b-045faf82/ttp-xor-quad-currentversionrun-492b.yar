rule TTP_XOR_QUAD_CurrentVersionRun_492b {
  strings:
    $key_492b = { 1a 44 [2] 3e 4a [2] 15 66 [2] 3b 44 [2] 2f 5f [2] 20 45 [2] 3e 58 [2] 3c 59 [2] 27 5f [2] 3b 58 [2] 27 77 }

  condition:
    any of them
}