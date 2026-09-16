rule TTP_XOR_MULT_DOSStub_1a4c {
  strings:
    $key_1a4c = { 4e 24 [2] 3a 3c [2] 7d 3e [2] 3a 2f [2] 74 23 [2] 78 29 [2] 6f 22 [2] 74 6c [2] 49 }

  condition:
    any of them
}