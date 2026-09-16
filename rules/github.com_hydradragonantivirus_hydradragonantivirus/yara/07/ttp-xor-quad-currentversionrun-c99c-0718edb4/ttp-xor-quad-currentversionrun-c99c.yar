rule TTP_XOR_QUAD_CurrentVersionRun_c99c {
  strings:
    $key_c99c = { 9a f3 [2] be fd [2] 95 d1 [2] bb f3 [2] af e8 [2] a0 f2 [2] be ef [2] bc ee [2] a7 e8 [2] bb ef [2] a7 c0 }

  condition:
    any of them
}