rule TTP_XOR_QUAD_CurrentVersionRun_007c {
  strings:
    $key_007c = { 53 13 [2] 77 1d [2] 5c 31 [2] 72 13 [2] 66 08 [2] 69 12 [2] 77 0f [2] 75 0e [2] 6e 08 [2] 72 0f [2] 6e 20 }

  condition:
    any of them
}