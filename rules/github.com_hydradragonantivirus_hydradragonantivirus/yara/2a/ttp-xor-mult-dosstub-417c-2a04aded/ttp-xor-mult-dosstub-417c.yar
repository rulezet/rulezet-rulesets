rule TTP_XOR_MULT_DOSStub_417c {
  strings:
    $key_417c = { 15 14 [2] 61 0c [2] 26 0e [2] 61 1f [2] 2f 13 [2] 23 19 [2] 34 12 [2] 2f 5c [2] 12 }

  condition:
    any of them
}