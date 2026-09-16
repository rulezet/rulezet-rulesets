rule TTP_XOR_MULT_DOSStub_badb {
  strings:
    $key_badb = { ee b3 [2] 9a ab [2] dd a9 [2] 9a b8 [2] d4 b4 [2] d8 be [2] cf b5 [2] d4 fb [2] e9 }

  condition:
    any of them
}