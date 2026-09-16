rule TTP_XOR_QUAD_CurrentVersionRun_e45b {
  strings:
    $key_e45b = { b7 34 [2] 93 3a [2] b8 16 [2] 96 34 [2] 82 2f [2] 8d 35 [2] 93 28 [2] 91 29 [2] 8a 2f [2] 96 28 [2] 8a 07 }

  condition:
    any of them
}