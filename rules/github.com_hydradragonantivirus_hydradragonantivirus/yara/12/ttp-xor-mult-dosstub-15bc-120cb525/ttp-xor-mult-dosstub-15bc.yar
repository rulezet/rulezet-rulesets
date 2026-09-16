rule TTP_XOR_MULT_DOSStub_15bc {
  strings:
    $key_15bc = { 41 d4 [2] 35 cc [2] 72 ce [2] 35 df [2] 7b d3 [2] 77 d9 [2] 60 d2 [2] 7b 9c [2] 46 }

  condition:
    any of them
}