rule TTP_XOR_MULT_DOSStub_8bde {
  strings:
    $key_8bde = { df b6 [2] ab ae [2] ec ac [2] ab bd [2] e5 b1 [2] e9 bb [2] fe b0 [2] e5 fe [2] d8 }

  condition:
    any of them
}