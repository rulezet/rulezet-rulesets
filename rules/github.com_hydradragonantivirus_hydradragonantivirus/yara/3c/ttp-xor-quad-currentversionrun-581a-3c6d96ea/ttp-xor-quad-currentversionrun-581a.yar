rule TTP_XOR_QUAD_CurrentVersionRun_581a {
  strings:
    $key_581a = { 0b 75 [2] 2f 7b [2] 04 57 [2] 2a 75 [2] 3e 6e [2] 31 74 [2] 2f 69 [2] 2d 68 [2] 36 6e [2] 2a 69 [2] 36 46 }

  condition:
    any of them
}