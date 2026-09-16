rule TTP_XOR_MULT_DOSStub_f1bc {
  strings:
    $key_f1bc = { a5 d4 [2] d1 cc [2] 96 ce [2] d1 df [2] 9f d3 [2] 93 d9 [2] 84 d2 [2] 9f 9c [2] a2 }

  condition:
    any of them
}