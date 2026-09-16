rule TTP_XOR_MULT_DOSStub_543f {
  strings:
    $key_543f = { 00 57 [2] 74 4f [2] 33 4d [2] 74 5c [2] 3a 50 [2] 36 5a [2] 21 51 [2] 3a 1f [2] 07 }

  condition:
    any of them
}