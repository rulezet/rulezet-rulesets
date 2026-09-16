rule TTP_XOR_QUAD_CurrentVersionRun_4d00 {
  strings:
    $key_4d00 = { 1e 6f [2] 3a 61 [2] 11 4d [2] 3f 6f [2] 2b 74 [2] 24 6e [2] 3a 73 [2] 38 72 [2] 23 74 [2] 3f 73 [2] 23 5c }

  condition:
    any of them
}