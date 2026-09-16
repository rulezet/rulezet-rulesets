rule TTP_XOR_MULT_DOSStub_3a4c {
  strings:
    $key_3a4c = { 6e 24 [2] 1a 3c [2] 5d 3e [2] 1a 2f [2] 54 23 [2] 58 29 [2] 4f 22 [2] 54 6c [2] 69 }

  condition:
    any of them
}