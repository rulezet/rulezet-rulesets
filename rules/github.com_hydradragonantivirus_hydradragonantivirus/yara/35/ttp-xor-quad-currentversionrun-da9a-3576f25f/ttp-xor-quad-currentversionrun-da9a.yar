rule TTP_XOR_QUAD_CurrentVersionRun_da9a {
  strings:
    $key_da9a = { 89 f5 [2] ad fb [2] 86 d7 [2] a8 f5 [2] bc ee [2] b3 f4 [2] ad e9 [2] af e8 [2] b4 ee [2] a8 e9 [2] b4 c6 }

  condition:
    any of them
}