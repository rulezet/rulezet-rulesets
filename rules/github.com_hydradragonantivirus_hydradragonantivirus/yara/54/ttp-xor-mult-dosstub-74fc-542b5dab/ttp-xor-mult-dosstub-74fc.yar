rule TTP_XOR_MULT_DOSStub_74fc {
  strings:
    $key_74fc = { 20 94 [2] 54 8c [2] 13 8e [2] 54 9f [2] 1a 93 [2] 16 99 [2] 01 92 [2] 1a dc [2] 27 }

  condition:
    any of them
}