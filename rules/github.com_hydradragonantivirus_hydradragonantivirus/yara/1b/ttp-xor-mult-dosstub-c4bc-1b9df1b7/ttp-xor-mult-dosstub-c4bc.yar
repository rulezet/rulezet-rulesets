rule TTP_XOR_MULT_DOSStub_c4bc {
  strings:
    $key_c4bc = { 90 d4 [2] e4 cc [2] a3 ce [2] e4 df [2] aa d3 [2] a6 d9 [2] b1 d2 [2] aa 9c [2] 97 }

  condition:
    any of them
}