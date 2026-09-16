rule TTP_XOR_MULT_DOSStub_5bb0 {
  strings:
    $key_5bb0 = { 0f d8 [2] 7b c0 [2] 3c c2 [2] 7b d3 [2] 35 df [2] 39 d5 [2] 2e de [2] 35 90 [2] 08 }

  condition:
    any of them
}