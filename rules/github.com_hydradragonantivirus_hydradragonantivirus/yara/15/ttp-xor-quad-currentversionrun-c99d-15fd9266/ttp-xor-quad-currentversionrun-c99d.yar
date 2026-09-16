rule TTP_XOR_QUAD_CurrentVersionRun_c99d {
  strings:
    $key_c99d = { 9a f2 [2] be fc [2] 95 d0 [2] bb f2 [2] af e9 [2] a0 f3 [2] be ee [2] bc ef [2] a7 e9 [2] bb ee [2] a7 c1 }

  condition:
    any of them
}