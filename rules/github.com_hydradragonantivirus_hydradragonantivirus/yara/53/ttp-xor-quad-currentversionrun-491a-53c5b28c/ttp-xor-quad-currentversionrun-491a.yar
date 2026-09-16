rule TTP_XOR_QUAD_CurrentVersionRun_491a {
  strings:
    $key_491a = { 1a 75 [2] 3e 7b [2] 15 57 [2] 3b 75 [2] 2f 6e [2] 20 74 [2] 3e 69 [2] 3c 68 [2] 27 6e [2] 3b 69 [2] 27 46 }

  condition:
    any of them
}