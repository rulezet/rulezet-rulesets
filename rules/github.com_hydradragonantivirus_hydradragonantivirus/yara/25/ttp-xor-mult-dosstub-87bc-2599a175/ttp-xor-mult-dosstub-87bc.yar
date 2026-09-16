rule TTP_XOR_MULT_DOSStub_87bc {
  strings:
    $key_87bc = { d3 d4 [2] a7 cc [2] e0 ce [2] a7 df [2] e9 d3 [2] e5 d9 [2] f2 d2 [2] e9 9c [2] d4 }

  condition:
    any of them
}