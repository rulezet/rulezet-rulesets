rule TTP_XOR_MULT_DOSStub_644c {
  strings:
    $key_644c = { 30 24 [2] 44 3c [2] 03 3e [2] 44 2f [2] 0a 23 [2] 06 29 [2] 11 22 [2] 0a 6c [2] 37 }

  condition:
    any of them
}