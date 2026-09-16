rule TTP_XOR_QUAD_CurrentVersionRun_4420 {
  strings:
    $key_4420 = { 17 4f [2] 33 41 [2] 18 6d [2] 36 4f [2] 22 54 [2] 2d 4e [2] 33 53 [2] 31 52 [2] 2a 54 [2] 36 53 [2] 2a 7c }

  condition:
    any of them
}