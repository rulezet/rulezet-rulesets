rule TTP_XOR_QUAD_CurrentVersionRun_4d50 {
  strings:
    $key_4d50 = { 1e 3f [2] 3a 31 [2] 11 1d [2] 3f 3f [2] 2b 24 [2] 24 3e [2] 3a 23 [2] 38 22 [2] 23 24 [2] 3f 23 [2] 23 0c }

  condition:
    any of them
}