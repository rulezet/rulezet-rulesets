rule TTP_XOR_QUAD_CurrentVersionRun_794a {
  strings:
    $key_794a = { 2a 25 [2] 0e 2b [2] 25 07 [2] 0b 25 [2] 1f 3e [2] 10 24 [2] 0e 39 [2] 0c 38 [2] 17 3e [2] 0b 39 [2] 17 16 }

  condition:
    any of them
}