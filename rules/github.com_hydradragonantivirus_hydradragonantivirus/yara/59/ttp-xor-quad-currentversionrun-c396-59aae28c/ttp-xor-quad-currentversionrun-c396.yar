rule TTP_XOR_QUAD_CurrentVersionRun_c396 {
  strings:
    $key_c396 = { 90 f9 [2] b4 f7 [2] 9f db [2] b1 f9 [2] a5 e2 [2] aa f8 [2] b4 e5 [2] b6 e4 [2] ad e2 [2] b1 e5 [2] ad ca }

  condition:
    any of them
}