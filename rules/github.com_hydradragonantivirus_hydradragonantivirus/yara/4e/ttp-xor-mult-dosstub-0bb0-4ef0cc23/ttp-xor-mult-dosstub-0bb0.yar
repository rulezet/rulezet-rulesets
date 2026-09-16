rule TTP_XOR_MULT_DOSStub_0bb0 {
  strings:
    $key_0bb0 = { 5f d8 [2] 2b c0 [2] 6c c2 [2] 2b d3 [2] 65 df [2] 69 d5 [2] 7e de [2] 65 90 [2] 58 }

  condition:
    any of them
}