rule TTP_XOR_MULT_DOSStub_eab0 {
  strings:
    $key_eab0 = { be d8 [2] ca c0 [2] 8d c2 [2] ca d3 [2] 84 df [2] 88 d5 [2] 9f de [2] 84 90 [2] b9 }

  condition:
    any of them
}