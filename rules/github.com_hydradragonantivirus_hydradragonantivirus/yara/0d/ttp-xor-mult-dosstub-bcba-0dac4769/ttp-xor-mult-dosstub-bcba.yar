rule TTP_XOR_MULT_DOSStub_bcba {
  strings:
    $key_bcba = { e8 d2 [2] 9c ca [2] db c8 [2] 9c d9 [2] d2 d5 [2] de df [2] c9 d4 [2] d2 9a [2] ef }

  condition:
    any of them
}