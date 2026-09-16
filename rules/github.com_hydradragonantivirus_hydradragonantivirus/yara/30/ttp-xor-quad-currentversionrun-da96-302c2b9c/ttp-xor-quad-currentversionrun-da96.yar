rule TTP_XOR_QUAD_CurrentVersionRun_da96 {
  strings:
    $key_da96 = { 89 f9 [2] ad f7 [2] 86 db [2] a8 f9 [2] bc e2 [2] b3 f8 [2] ad e5 [2] af e4 [2] b4 e2 [2] a8 e5 [2] b4 ca }

  condition:
    any of them
}