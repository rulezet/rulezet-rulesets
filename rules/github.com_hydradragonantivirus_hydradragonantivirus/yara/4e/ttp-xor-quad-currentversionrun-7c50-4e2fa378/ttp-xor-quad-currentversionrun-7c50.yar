rule TTP_XOR_QUAD_CurrentVersionRun_7c50 {
  strings:
    $key_7c50 = { 2f 3f [2] 0b 31 [2] 20 1d [2] 0e 3f [2] 1a 24 [2] 15 3e [2] 0b 23 [2] 09 22 [2] 12 24 [2] 0e 23 [2] 12 0c }

  condition:
    any of them
}