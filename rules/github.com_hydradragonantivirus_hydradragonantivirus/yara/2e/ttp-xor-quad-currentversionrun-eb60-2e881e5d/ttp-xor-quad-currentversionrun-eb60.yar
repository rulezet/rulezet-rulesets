rule TTP_XOR_QUAD_CurrentVersionRun_eb60 {
  strings:
    $key_eb60 = { b8 0f [2] 9c 01 [2] b7 2d [2] 99 0f [2] 8d 14 [2] 82 0e [2] 9c 13 [2] 9e 12 [2] 85 14 [2] 99 13 [2] 85 3c }

  condition:
    any of them
}