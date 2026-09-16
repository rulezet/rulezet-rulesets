rule TTP_XOR_MULT_DOSStub_1bde {
  strings:
    $key_1bde = { 4f b6 [2] 3b ae [2] 7c ac [2] 3b bd [2] 75 b1 [2] 79 bb [2] 6e b0 [2] 75 fe [2] 48 }

  condition:
    any of them
}