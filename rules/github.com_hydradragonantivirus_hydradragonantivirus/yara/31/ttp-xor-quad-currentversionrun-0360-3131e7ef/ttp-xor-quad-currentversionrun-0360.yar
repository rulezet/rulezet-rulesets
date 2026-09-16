rule TTP_XOR_QUAD_CurrentVersionRun_0360 {
  strings:
    $key_0360 = { 50 0f [2] 74 01 [2] 5f 2d [2] 71 0f [2] 65 14 [2] 6a 0e [2] 74 13 [2] 76 12 [2] 6d 14 [2] 71 13 [2] 6d 3c }

  condition:
    any of them
}