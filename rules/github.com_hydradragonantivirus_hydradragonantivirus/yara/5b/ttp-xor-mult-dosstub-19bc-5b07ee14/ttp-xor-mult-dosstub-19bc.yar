rule TTP_XOR_MULT_DOSStub_19bc {
  strings:
    $key_19bc = { 4d d4 [2] 39 cc [2] 7e ce [2] 39 df [2] 77 d3 [2] 7b d9 [2] 6c d2 [2] 77 9c [2] 4a }

  condition:
    any of them
}