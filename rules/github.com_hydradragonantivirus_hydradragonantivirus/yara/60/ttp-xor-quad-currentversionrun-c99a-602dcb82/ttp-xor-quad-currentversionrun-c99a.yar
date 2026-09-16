rule TTP_XOR_QUAD_CurrentVersionRun_c99a {
  strings:
    $key_c99a = { 9a f5 [2] be fb [2] 95 d7 [2] bb f5 [2] af ee [2] a0 f4 [2] be e9 [2] bc e8 [2] a7 ee [2] bb e9 [2] a7 c6 }

  condition:
    any of them
}