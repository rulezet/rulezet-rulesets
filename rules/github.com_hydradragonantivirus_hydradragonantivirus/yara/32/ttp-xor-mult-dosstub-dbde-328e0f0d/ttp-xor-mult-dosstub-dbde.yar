rule TTP_XOR_MULT_DOSStub_dbde {
  strings:
    $key_dbde = { 8f b6 [2] fb ae [2] bc ac [2] fb bd [2] b5 b1 [2] b9 bb [2] ae b0 [2] b5 fe [2] 88 }

  condition:
    any of them
}