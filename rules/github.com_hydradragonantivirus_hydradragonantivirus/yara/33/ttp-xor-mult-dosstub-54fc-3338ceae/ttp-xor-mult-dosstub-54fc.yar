rule TTP_XOR_MULT_DOSStub_54fc {
  strings:
    $key_54fc = { 00 94 [2] 74 8c [2] 33 8e [2] 74 9f [2] 3a 93 [2] 36 99 [2] 21 92 [2] 3a dc [2] 07 }

  condition:
    any of them
}