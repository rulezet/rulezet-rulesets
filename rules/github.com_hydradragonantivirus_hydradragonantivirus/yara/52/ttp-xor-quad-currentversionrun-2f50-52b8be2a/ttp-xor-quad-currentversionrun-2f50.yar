rule TTP_XOR_QUAD_CurrentVersionRun_2f50 {
  strings:
    $key_2f50 = { 7c 3f [2] 58 31 [2] 73 1d [2] 5d 3f [2] 49 24 [2] 46 3e [2] 58 23 [2] 5a 22 [2] 41 24 [2] 5d 23 [2] 41 0c }

  condition:
    any of them
}