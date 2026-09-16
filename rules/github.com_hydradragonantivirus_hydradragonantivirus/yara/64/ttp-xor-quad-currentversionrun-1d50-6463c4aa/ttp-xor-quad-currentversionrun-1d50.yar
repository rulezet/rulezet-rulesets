rule TTP_XOR_QUAD_CurrentVersionRun_1d50 {
  strings:
    $key_1d50 = { 4e 3f [2] 6a 31 [2] 41 1d [2] 6f 3f [2] 7b 24 [2] 74 3e [2] 6a 23 [2] 68 22 [2] 73 24 [2] 6f 23 [2] 73 0c }

  condition:
    any of them
}