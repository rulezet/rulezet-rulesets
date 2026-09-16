rule TTP_XOR_QUAD_CurrentVersionRun_c370 {
  strings:
    $key_c370 = { 90 1f [2] b4 11 [2] 9f 3d [2] b1 1f [2] a5 04 [2] aa 1e [2] b4 03 [2] b6 02 [2] ad 04 [2] b1 03 [2] ad 2c }

  condition:
    any of them
}