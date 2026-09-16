rule TTP_XOR_QUAD_CurrentVersionRun_da80 {
  strings:
    $key_da80 = { 89 ef [2] ad e1 [2] 86 cd [2] a8 ef [2] bc f4 [2] b3 ee [2] ad f3 [2] af f2 [2] b4 f4 [2] a8 f3 [2] b4 dc }

  condition:
    any of them
}