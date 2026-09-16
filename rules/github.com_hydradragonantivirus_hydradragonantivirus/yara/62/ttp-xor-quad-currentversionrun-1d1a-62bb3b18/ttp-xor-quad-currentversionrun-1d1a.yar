rule TTP_XOR_QUAD_CurrentVersionRun_1d1a {
  strings:
    $key_1d1a = { 4e 75 [2] 6a 7b [2] 41 57 [2] 6f 75 [2] 7b 6e [2] 74 74 [2] 6a 69 [2] 68 68 [2] 73 6e [2] 6f 69 [2] 73 46 }

  condition:
    any of them
}