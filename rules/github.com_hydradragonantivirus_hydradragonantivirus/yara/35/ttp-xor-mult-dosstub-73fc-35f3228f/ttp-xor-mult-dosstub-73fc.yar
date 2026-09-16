rule TTP_XOR_MULT_DOSStub_73fc {
  strings:
    $key_73fc = { 27 94 [2] 53 8c [2] 14 8e [2] 53 9f [2] 1d 93 [2] 11 99 [2] 06 92 [2] 1d dc [2] 20 }

  condition:
    any of them
}