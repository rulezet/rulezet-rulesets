rule TTP_XOR_QUAD_CurrentVersionRun_622b {
  strings:
    $key_622b = { 31 44 [2] 15 4a [2] 3e 66 [2] 10 44 [2] 04 5f [2] 0b 45 [2] 15 58 [2] 17 59 [2] 0c 5f [2] 10 58 [2] 0c 77 }

  condition:
    any of them
}