rule TTP_XOR_QUAD_CurrentVersionRun_c442 {
  strings:
    $key_c442 = { 97 2d [2] b3 23 [2] 98 0f [2] b6 2d [2] a2 36 [2] ad 2c [2] b3 31 [2] b1 30 [2] aa 36 [2] b6 31 [2] aa 1e }

  condition:
    any of them
}