rule TTP_XOR_QUAD_CurrentVersionRun_7f50 {
  strings:
    $key_7f50 = { 2c 3f [2] 08 31 [2] 23 1d [2] 0d 3f [2] 19 24 [2] 16 3e [2] 08 23 [2] 0a 22 [2] 11 24 [2] 0d 23 [2] 11 0c }

  condition:
    any of them
}