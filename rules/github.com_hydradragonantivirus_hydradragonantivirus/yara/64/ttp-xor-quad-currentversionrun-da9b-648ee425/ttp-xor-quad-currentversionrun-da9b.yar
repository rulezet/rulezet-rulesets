rule TTP_XOR_QUAD_CurrentVersionRun_da9b {
  strings:
    $key_da9b = { 89 f4 [2] ad fa [2] 86 d6 [2] a8 f4 [2] bc ef [2] b3 f5 [2] ad e8 [2] af e9 [2] b4 ef [2] a8 e8 [2] b4 c7 }

  condition:
    any of them
}