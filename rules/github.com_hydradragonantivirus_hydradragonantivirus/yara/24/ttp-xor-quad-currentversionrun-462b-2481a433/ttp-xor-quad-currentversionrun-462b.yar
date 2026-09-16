rule TTP_XOR_QUAD_CurrentVersionRun_462b {
  strings:
    $key_462b = { 15 44 [2] 31 4a [2] 1a 66 [2] 34 44 [2] 20 5f [2] 2f 45 [2] 31 58 [2] 33 59 [2] 28 5f [2] 34 58 [2] 28 77 }

  condition:
    any of them
}