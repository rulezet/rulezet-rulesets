rule TTP_XOR_MULT_DOSStub_09b0 {
  strings:
    $key_09b0 = { 5d d8 [2] 29 c0 [2] 6e c2 [2] 29 d3 [2] 67 df [2] 6b d5 [2] 7c de [2] 67 90 [2] 5a }

  condition:
    any of them
}