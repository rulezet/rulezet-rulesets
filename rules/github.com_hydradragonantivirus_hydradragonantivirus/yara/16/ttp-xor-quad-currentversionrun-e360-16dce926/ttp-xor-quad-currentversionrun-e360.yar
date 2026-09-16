rule TTP_XOR_QUAD_CurrentVersionRun_e360 {
  strings:
    $key_e360 = { b0 0f [2] 94 01 [2] bf 2d [2] 91 0f [2] 85 14 [2] 8a 0e [2] 94 13 [2] 96 12 [2] 8d 14 [2] 91 13 [2] 8d 3c }

  condition:
    any of them
}