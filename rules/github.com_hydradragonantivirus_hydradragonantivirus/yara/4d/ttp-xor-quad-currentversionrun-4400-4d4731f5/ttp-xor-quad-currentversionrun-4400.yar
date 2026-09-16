rule TTP_XOR_QUAD_CurrentVersionRun_4400 {
  strings:
    $key_4400 = { 17 6f [2] 33 61 [2] 18 4d [2] 36 6f [2] 22 74 [2] 2d 6e [2] 33 73 [2] 31 72 [2] 2a 74 [2] 36 73 [2] 2a 5c }

  condition:
    any of them
}