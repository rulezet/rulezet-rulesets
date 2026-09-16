rule TTP_XOR_QUAD_CurrentVersionRun_7750 {
  strings:
    $key_7750 = { 24 3f [2] 00 31 [2] 2b 1d [2] 05 3f [2] 11 24 [2] 1e 3e [2] 00 23 [2] 02 22 [2] 19 24 [2] 05 23 [2] 19 0c }

  condition:
    any of them
}