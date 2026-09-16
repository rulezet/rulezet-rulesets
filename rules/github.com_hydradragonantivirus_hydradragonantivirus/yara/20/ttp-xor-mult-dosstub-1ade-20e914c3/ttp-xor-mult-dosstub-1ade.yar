rule TTP_XOR_MULT_DOSStub_1ade {
  strings:
    $key_1ade = { 4e b6 [2] 3a ae [2] 7d ac [2] 3a bd [2] 74 b1 [2] 78 bb [2] 6f b0 [2] 74 fe [2] 49 }

  condition:
    any of them
}