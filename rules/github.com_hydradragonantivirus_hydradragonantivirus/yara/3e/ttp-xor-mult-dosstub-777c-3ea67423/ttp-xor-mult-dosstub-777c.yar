rule TTP_XOR_MULT_DOSStub_777c {
  strings:
    $key_777c = { 23 14 [2] 57 0c [2] 10 0e [2] 57 1f [2] 19 13 [2] 15 19 [2] 02 12 [2] 19 5c [2] 24 }

  condition:
    any of them
}