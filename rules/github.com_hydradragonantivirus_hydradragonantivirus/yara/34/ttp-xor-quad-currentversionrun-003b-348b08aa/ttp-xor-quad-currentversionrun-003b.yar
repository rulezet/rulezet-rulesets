rule TTP_XOR_QUAD_CurrentVersionRun_003b {
  strings:
    $key_003b = { 53 54 [2] 77 5a [2] 5c 76 [2] 72 54 [2] 66 4f [2] 69 55 [2] 77 48 [2] 75 49 [2] 6e 4f [2] 72 48 [2] 6e 67 }

  condition:
    any of them
}