rule TTP_XOR_QUAD_CurrentVersionRun_551a {
  strings:
    $key_551a = { 06 75 [2] 22 7b [2] 09 57 [2] 27 75 [2] 33 6e [2] 3c 74 [2] 22 69 [2] 20 68 [2] 3b 6e [2] 27 69 [2] 3b 46 }

  condition:
    any of them
}