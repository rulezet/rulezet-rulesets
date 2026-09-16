rule TTP_XOR_MULT_DOSStub_badd {
  strings:
    $key_badd = { ee b5 [2] 9a ad [2] dd af [2] 9a be [2] d4 b2 [2] d8 b8 [2] cf b3 [2] d4 fd [2] e9 }

  condition:
    any of them
}