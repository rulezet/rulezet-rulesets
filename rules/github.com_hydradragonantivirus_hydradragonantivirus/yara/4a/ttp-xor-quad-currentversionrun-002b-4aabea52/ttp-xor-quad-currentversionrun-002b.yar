rule TTP_XOR_QUAD_CurrentVersionRun_002b {
  strings:
    $key_002b = { 53 44 [2] 77 4a [2] 5c 66 [2] 72 44 [2] 66 5f [2] 69 45 [2] 77 58 [2] 75 59 [2] 6e 5f [2] 72 58 [2] 6e 77 }

  condition:
    any of them
}