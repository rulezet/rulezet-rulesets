rule TTP_XOR_QUAD_CurrentVersionRun_2a1d {
  strings:
    $key_2a1d = { 79 72 [2] 5d 7c [2] 76 50 [2] 58 72 [2] 4c 69 [2] 43 73 [2] 5d 6e [2] 5f 6f [2] 44 69 [2] 58 6e [2] 44 41 }

  condition:
    any of them
}