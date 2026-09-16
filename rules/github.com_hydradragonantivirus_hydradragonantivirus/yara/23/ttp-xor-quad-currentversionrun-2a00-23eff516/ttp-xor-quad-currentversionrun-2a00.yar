rule TTP_XOR_QUAD_CurrentVersionRun_2a00 {
  strings:
    $key_2a00 = { 79 6f [2] 5d 61 [2] 76 4d [2] 58 6f [2] 4c 74 [2] 43 6e [2] 5d 73 [2] 5f 72 [2] 44 74 [2] 58 73 [2] 44 5c }

  condition:
    any of them
}