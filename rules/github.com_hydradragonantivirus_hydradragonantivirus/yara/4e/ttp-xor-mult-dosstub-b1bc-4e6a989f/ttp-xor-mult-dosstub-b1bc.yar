rule TTP_XOR_MULT_DOSStub_b1bc {
  strings:
    $key_b1bc = { e5 d4 [2] 91 cc [2] d6 ce [2] 91 df [2] df d3 [2] d3 d9 [2] c4 d2 [2] df 9c [2] e2 }

  condition:
    any of them
}