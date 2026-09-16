rule TTP_XOR_MULT_DOSStub_543d {
  strings:
    $key_543d = { 00 55 [2] 74 4d [2] 33 4f [2] 74 5e [2] 3a 52 [2] 36 58 [2] 21 53 [2] 3a 1d [2] 07 }

  condition:
    any of them
}