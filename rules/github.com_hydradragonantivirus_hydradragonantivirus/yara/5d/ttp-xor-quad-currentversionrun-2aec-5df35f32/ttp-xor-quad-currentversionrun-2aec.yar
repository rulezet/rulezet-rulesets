rule TTP_XOR_QUAD_CurrentVersionRun_2aec {
  strings:
    $key_2aec = { 79 83 [2] 5d 8d [2] 76 a1 [2] 58 83 [2] 4c 98 [2] 43 82 [2] 5d 9f [2] 5f 9e [2] 44 98 [2] 58 9f [2] 44 b0 }

  condition:
    any of them
}