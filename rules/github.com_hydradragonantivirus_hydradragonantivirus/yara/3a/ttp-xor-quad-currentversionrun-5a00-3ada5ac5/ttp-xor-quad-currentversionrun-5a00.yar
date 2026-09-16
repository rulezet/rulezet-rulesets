rule TTP_XOR_QUAD_CurrentVersionRun_5a00 {
  strings:
    $key_5a00 = { 09 6f [2] 2d 61 [2] 06 4d [2] 28 6f [2] 3c 74 [2] 33 6e [2] 2d 73 [2] 2f 72 [2] 34 74 [2] 28 73 [2] 34 5c }

  condition:
    any of them
}