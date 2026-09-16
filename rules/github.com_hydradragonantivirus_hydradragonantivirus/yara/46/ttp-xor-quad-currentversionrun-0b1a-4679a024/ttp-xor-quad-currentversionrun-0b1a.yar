rule TTP_XOR_QUAD_CurrentVersionRun_0b1a {
  strings:
    $key_0b1a = { 58 75 [2] 7c 7b [2] 57 57 [2] 79 75 [2] 6d 6e [2] 62 74 [2] 7c 69 [2] 7e 68 [2] 65 6e [2] 79 69 [2] 65 46 }

  condition:
    any of them
}