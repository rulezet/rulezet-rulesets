rule TTP_XOR_QUAD_CurrentVersionRun_6360 {
  strings:
    $key_6360 = { 30 0f [2] 14 01 [2] 3f 2d [2] 11 0f [2] 05 14 [2] 0a 0e [2] 14 13 [2] 16 12 [2] 0d 14 [2] 11 13 [2] 0d 3c }

  condition:
    any of them
}