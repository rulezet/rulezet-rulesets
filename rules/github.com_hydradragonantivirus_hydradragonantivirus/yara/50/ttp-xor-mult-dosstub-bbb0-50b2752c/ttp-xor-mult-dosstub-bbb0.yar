rule TTP_XOR_MULT_DOSStub_bbb0 {
  strings:
    $key_bbb0 = { ef d8 [2] 9b c0 [2] dc c2 [2] 9b d3 [2] d5 df [2] d9 d5 [2] ce de [2] d5 90 [2] e8 }

  condition:
    any of them
}