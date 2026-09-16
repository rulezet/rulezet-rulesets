rule TTP_XOR_MULT_DOSStub_2bde {
  strings:
    $key_2bde = { 7f b6 [2] 0b ae [2] 4c ac [2] 0b bd [2] 45 b1 [2] 49 bb [2] 5e b0 [2] 45 fe [2] 78 }

  condition:
    any of them
}