rule TTP_XOR_QUAD_CurrentVersionRun_da81 {
  strings:
    $key_da81 = { 89 ee [2] ad e0 [2] 86 cc [2] a8 ee [2] bc f5 [2] b3 ef [2] ad f2 [2] af f3 [2] b4 f5 [2] a8 f2 [2] b4 dd }

  condition:
    any of them
}