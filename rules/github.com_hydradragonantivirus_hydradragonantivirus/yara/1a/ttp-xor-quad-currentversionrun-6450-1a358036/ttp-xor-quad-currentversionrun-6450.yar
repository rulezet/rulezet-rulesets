rule TTP_XOR_QUAD_CurrentVersionRun_6450 {
  strings:
    $key_6450 = { 37 3f [2] 13 31 [2] 38 1d [2] 16 3f [2] 02 24 [2] 0d 3e [2] 13 23 [2] 11 22 [2] 0a 24 [2] 16 23 [2] 0a 0c }

  condition:
    any of them
}