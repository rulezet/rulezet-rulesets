rule TTP_XOR_QUAD_CurrentVersionRun_191a {
  strings:
    $key_191a = { 4a 75 [2] 6e 7b [2] 45 57 [2] 6b 75 [2] 7f 6e [2] 70 74 [2] 6e 69 [2] 6c 68 [2] 77 6e [2] 6b 69 [2] 77 46 }

  condition:
    any of them
}