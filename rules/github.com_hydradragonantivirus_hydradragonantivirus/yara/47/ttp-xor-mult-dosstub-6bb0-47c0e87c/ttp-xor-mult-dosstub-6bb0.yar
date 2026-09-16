rule TTP_XOR_MULT_DOSStub_6bb0 {
  strings:
    $key_6bb0 = { 3f d8 [2] 4b c0 [2] 0c c2 [2] 4b d3 [2] 05 df [2] 09 d5 [2] 1e de [2] 05 90 [2] 38 }

  condition:
    any of them
}