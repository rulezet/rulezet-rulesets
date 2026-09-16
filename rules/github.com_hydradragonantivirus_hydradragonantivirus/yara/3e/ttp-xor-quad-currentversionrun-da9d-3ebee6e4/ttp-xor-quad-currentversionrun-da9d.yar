rule TTP_XOR_QUAD_CurrentVersionRun_da9d {
  strings:
    $key_da9d = { 89 f2 [2] ad fc [2] 86 d0 [2] a8 f2 [2] bc e9 [2] b3 f3 [2] ad ee [2] af ef [2] b4 e9 [2] a8 ee [2] b4 c1 }

  condition:
    any of them
}