rule TTP_XOR_MULT_DOSStub_b5bc {
  strings:
    $key_b5bc = { e1 d4 [2] 95 cc [2] d2 ce [2] 95 df [2] db d3 [2] d7 d9 [2] c0 d2 [2] db 9c [2] e6 }

  condition:
    any of them
}