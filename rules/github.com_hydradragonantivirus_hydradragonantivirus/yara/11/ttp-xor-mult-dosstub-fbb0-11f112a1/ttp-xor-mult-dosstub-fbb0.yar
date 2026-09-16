rule TTP_XOR_MULT_DOSStub_fbb0 {
  strings:
    $key_fbb0 = { af d8 [2] db c0 [2] 9c c2 [2] db d3 [2] 95 df [2] 99 d5 [2] 8e de [2] 95 90 [2] a8 }

  condition:
    any of them
}