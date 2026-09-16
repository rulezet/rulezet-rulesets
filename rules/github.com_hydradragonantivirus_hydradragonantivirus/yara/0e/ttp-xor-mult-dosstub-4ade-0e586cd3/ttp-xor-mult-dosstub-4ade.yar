rule TTP_XOR_MULT_DOSStub_4ade {
  strings:
    $key_4ade = { 1e b6 [2] 6a ae [2] 2d ac [2] 6a bd [2] 24 b1 [2] 28 bb [2] 3f b0 [2] 24 fe [2] 19 }

  condition:
    any of them
}