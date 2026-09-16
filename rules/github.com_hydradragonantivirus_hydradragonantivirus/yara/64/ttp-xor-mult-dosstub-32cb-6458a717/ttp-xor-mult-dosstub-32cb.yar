rule TTP_XOR_MULT_DOSStub_32cb {
  strings:
    $key_32cb = { 66 a3 [2] 12 bb [2] 55 b9 [2] 12 a8 [2] 5c a4 [2] 50 ae [2] 47 a5 [2] 5c eb [2] 61 }

  condition:
    any of them
}