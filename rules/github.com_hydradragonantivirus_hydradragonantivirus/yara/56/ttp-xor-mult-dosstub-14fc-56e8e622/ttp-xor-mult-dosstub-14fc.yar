rule TTP_XOR_MULT_DOSStub_14fc {
  strings:
    $key_14fc = { 40 94 [2] 34 8c [2] 73 8e [2] 34 9f [2] 7a 93 [2] 76 99 [2] 61 92 [2] 7a dc [2] 47 }

  condition:
    any of them
}