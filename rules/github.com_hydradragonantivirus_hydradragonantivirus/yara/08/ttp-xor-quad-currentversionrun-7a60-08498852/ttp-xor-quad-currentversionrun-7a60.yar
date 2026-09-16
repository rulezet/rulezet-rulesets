rule TTP_XOR_QUAD_CurrentVersionRun_7a60 {
  strings:
    $key_7a60 = { 29 0f [2] 0d 01 [2] 26 2d [2] 08 0f [2] 1c 14 [2] 13 0e [2] 0d 13 [2] 0f 12 [2] 14 14 [2] 08 13 [2] 14 3c }

  condition:
    any of them
}