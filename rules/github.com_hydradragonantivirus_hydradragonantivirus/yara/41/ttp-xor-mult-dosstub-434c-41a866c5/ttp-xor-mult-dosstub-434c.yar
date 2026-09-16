rule TTP_XOR_MULT_DOSStub_434c {
  strings:
    $key_434c = { 17 24 [2] 63 3c [2] 24 3e [2] 63 2f [2] 2d 23 [2] 21 29 [2] 36 22 [2] 2d 6c [2] 10 }

  condition:
    any of them
}