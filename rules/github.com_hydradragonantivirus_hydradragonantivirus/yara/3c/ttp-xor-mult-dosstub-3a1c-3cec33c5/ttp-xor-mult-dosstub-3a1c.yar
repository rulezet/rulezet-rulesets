rule TTP_XOR_MULT_DOSStub_3a1c {
  strings:
    $key_3a1c = { 6e 74 [2] 1a 6c [2] 5d 6e [2] 1a 7f [2] 54 73 [2] 58 79 [2] 4f 72 [2] 54 3c [2] 69 }

  condition:
    any of them
}