rule TTP_XOR_QUAD_CurrentVersionRun_da86 {
  strings:
    $key_da86 = { 89 e9 [2] ad e7 [2] 86 cb [2] a8 e9 [2] bc f2 [2] b3 e8 [2] ad f5 [2] af f4 [2] b4 f2 [2] a8 f5 [2] b4 da }

  condition:
    any of them
}