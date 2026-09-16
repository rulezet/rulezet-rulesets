rule TTP_XOR_MULT_DOSStub_b6bc {
  strings:
    $key_b6bc = { e2 d4 [2] 96 cc [2] d1 ce [2] 96 df [2] d8 d3 [2] d4 d9 [2] c3 d2 [2] d8 9c [2] e5 }

  condition:
    any of them
}