rule TTP_XOR_MULT_DOSStub_07bc {
  strings:
    $key_07bc = { 53 d4 [2] 27 cc [2] 60 ce [2] 27 df [2] 69 d3 [2] 65 d9 [2] 72 d2 [2] 69 9c [2] 54 }

  condition:
    any of them
}