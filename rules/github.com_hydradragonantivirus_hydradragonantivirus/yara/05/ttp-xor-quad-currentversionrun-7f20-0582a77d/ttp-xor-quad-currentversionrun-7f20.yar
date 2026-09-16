rule TTP_XOR_QUAD_CurrentVersionRun_7f20 {
  strings:
    $key_7f20 = { 2c 4f [2] 08 41 [2] 23 6d [2] 0d 4f [2] 19 54 [2] 16 4e [2] 08 53 [2] 0a 52 [2] 11 54 [2] 0d 53 [2] 11 7c }

  condition:
    any of them
}