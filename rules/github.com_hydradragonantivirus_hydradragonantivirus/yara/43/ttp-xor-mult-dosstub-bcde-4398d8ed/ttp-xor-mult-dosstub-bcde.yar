rule TTP_XOR_MULT_DOSStub_bcde {
  strings:
    $key_bcde = { e8 b6 [2] 9c ae [2] db ac [2] 9c bd [2] d2 b1 [2] de bb [2] c9 b0 [2] d2 fe [2] ef }

  condition:
    any of them
}