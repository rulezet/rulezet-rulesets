rule TTP_XOR_QUAD_CurrentVersionRun_3100 {
  strings:
    $key_3100 = { 62 6f [2] 46 61 [2] 6d 4d [2] 43 6f [2] 57 74 [2] 58 6e [2] 46 73 [2] 44 72 [2] 5f 74 [2] 43 73 [2] 5f 5c }

  condition:
    any of them
}