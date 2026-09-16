rule TTP_XOR_MULT_DOSStub_f3ab {
  strings:
    $key_f3ab = { a7 c3 [2] d3 db [2] 94 d9 [2] d3 c8 [2] 9d c4 [2] 91 ce [2] 86 c5 [2] 9d 8b [2] a0 }

  condition:
    any of them
}