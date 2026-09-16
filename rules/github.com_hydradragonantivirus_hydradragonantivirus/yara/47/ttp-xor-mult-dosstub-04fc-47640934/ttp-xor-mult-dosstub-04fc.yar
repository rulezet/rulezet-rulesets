rule TTP_XOR_MULT_DOSStub_04fc {
  strings:
    $key_04fc = { 50 94 [2] 24 8c [2] 63 8e [2] 24 9f [2] 6a 93 [2] 66 99 [2] 71 92 [2] 6a dc [2] 57 }

  condition:
    any of them
}