rule TTP_XOR_MULT_DOSStub_647c {
  strings:
    $key_647c = { 30 14 [2] 44 0c [2] 03 0e [2] 44 1f [2] 0a 13 [2] 06 19 [2] 11 12 [2] 0a 5c [2] 37 }

  condition:
    any of them
}