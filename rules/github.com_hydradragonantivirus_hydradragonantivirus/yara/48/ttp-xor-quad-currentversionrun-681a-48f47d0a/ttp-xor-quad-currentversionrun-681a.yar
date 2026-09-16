rule TTP_XOR_QUAD_CurrentVersionRun_681a {
  strings:
    $key_681a = { 3b 75 [2] 1f 7b [2] 34 57 [2] 1a 75 [2] 0e 6e [2] 01 74 [2] 1f 69 [2] 1d 68 [2] 06 6e [2] 1a 69 [2] 06 46 }

  condition:
    any of them
}