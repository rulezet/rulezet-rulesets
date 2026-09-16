rule TTP_XOR_MULT_DOSStub_2a4c {
  strings:
    $key_2a4c = { 7e 24 [2] 0a 3c [2] 4d 3e [2] 0a 2f [2] 44 23 [2] 48 29 [2] 5f 22 [2] 44 6c [2] 79 }

  condition:
    any of them
}