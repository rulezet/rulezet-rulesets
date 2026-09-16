rule TTP_XOR_MULT_DOSStub_f5bc {
  strings:
    $key_f5bc = { a1 d4 [2] d5 cc [2] 92 ce [2] d5 df [2] 9b d3 [2] 97 d9 [2] 80 d2 [2] 9b 9c [2] a6 }

  condition:
    any of them
}