rule TTP_XOR_MULT_DOSStub_45fc {
  strings:
    $key_45fc = { 11 94 [2] 65 8c [2] 22 8e [2] 65 9f [2] 2b 93 [2] 27 99 [2] 30 92 [2] 2b dc [2] 16 }

  condition:
    any of them
}