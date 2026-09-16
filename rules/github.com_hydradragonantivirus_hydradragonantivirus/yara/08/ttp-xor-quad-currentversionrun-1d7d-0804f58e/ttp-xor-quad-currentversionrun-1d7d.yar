rule TTP_XOR_QUAD_CurrentVersionRun_1d7d {
  strings:
    $key_1d7d = { 4e 12 [2] 6a 1c [2] 41 30 [2] 6f 12 [2] 7b 09 [2] 74 13 [2] 6a 0e [2] 68 0f [2] 73 09 [2] 6f 0e [2] 73 21 }

  condition:
    any of them
}