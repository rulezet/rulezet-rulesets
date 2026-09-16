rule TTP_XOR_MULT_DOSStub_02bc {
  strings:
    $key_02bc = { 56 d4 [2] 22 cc [2] 65 ce [2] 22 df [2] 6c d3 [2] 60 d9 [2] 77 d2 [2] 6c 9c [2] 51 }

  condition:
    any of them
}