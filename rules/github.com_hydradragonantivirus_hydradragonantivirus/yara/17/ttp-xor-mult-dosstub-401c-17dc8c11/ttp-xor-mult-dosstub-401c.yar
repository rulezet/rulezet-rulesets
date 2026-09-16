rule TTP_XOR_MULT_DOSStub_401c {
  strings:
    $key_401c = { 14 74 [2] 60 6c [2] 27 6e [2] 60 7f [2] 2e 73 [2] 22 79 [2] 35 72 [2] 2e 3c [2] 13 }

  condition:
    any of them
}