rule TTP_XOR_MULT_DOSStub_1a1c {
  strings:
    $key_1a1c = { 4e 74 [2] 3a 6c [2] 7d 6e [2] 3a 7f [2] 74 73 [2] 78 79 [2] 6f 72 [2] 74 3c [2] 49 }

  condition:
    any of them
}