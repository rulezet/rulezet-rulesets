rule TTP_XOR_QUAD_CurrentVersionRun_6ffa {
  strings:
    $key_6ffa = { 3c 95 [2] 18 9b [2] 33 b7 [2] 1d 95 [2] 09 8e [2] 06 94 [2] 18 89 [2] 1a 88 [2] 01 8e [2] 1d 89 [2] 01 a6 }

  condition:
    any of them
}