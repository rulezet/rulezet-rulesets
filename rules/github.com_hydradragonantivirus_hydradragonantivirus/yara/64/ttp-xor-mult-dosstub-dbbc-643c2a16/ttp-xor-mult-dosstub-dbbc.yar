rule TTP_XOR_MULT_DOSStub_dbbc {
  strings:
    $key_dbbc = { 8f d4 [2] fb cc [2] bc ce [2] fb df [2] b5 d3 [2] b9 d9 [2] ae d2 [2] b5 9c [2] 88 }

  condition:
    any of them
}