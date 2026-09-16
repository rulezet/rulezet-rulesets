rule TTP_XOR_MULT_DOSStub_3ade {
  strings:
    $key_3ade = { 6e b6 [2] 1a ae [2] 5d ac [2] 1a bd [2] 54 b1 [2] 58 bb [2] 4f b0 [2] 54 fe [2] 69 }

  condition:
    any of them
}