rule TTP_XOR_MULT_DOSStub_23bc {
  strings:
    $key_23bc = { 77 d4 [2] 03 cc [2] 44 ce [2] 03 df [2] 4d d3 [2] 41 d9 [2] 56 d2 [2] 4d 9c [2] 70 }

  condition:
    any of them
}