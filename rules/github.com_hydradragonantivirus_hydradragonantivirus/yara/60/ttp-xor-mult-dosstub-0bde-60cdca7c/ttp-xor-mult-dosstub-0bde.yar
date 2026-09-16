rule TTP_XOR_MULT_DOSStub_0bde {
  strings:
    $key_0bde = { 5f b6 [2] 2b ae [2] 6c ac [2] 2b bd [2] 65 b1 [2] 69 bb [2] 7e b0 [2] 65 fe [2] 58 }

  condition:
    any of them
}