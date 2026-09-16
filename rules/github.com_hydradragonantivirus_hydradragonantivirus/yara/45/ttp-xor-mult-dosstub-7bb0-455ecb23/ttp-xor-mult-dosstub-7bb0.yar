rule TTP_XOR_MULT_DOSStub_7bb0 {
  strings:
    $key_7bb0 = { 2f d8 [2] 5b c0 [2] 1c c2 [2] 5b d3 [2] 15 df [2] 19 d5 [2] 0e de [2] 15 90 [2] 28 }

  condition:
    any of them
}