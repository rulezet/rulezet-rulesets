rule TTP_XOR_QUAD_CurrentVersionRun_792b {
  strings:
    $key_792b = { 2a 44 [2] 0e 4a [2] 25 66 [2] 0b 44 [2] 1f 5f [2] 10 45 [2] 0e 58 [2] 0c 59 [2] 17 5f [2] 0b 58 [2] 17 77 }

  condition:
    any of them
}