rule TTP_XOR_QUAD_CurrentVersionRun_3a60 {
  strings:
    $key_3a60 = { 69 0f [2] 4d 01 [2] 66 2d [2] 48 0f [2] 5c 14 [2] 53 0e [2] 4d 13 [2] 4f 12 [2] 54 14 [2] 48 13 [2] 54 3c }

  condition:
    any of them
}