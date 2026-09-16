rule TTP_XOR_MULT_DOSStub_83bc {
  strings:
    $key_83bc = { d7 d4 [2] a3 cc [2] e4 ce [2] a3 df [2] ed d3 [2] e1 d9 [2] f6 d2 [2] ed 9c [2] d0 }

  condition:
    any of them
}