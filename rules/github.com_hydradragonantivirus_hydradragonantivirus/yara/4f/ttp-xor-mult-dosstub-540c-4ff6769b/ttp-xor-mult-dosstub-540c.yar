rule TTP_XOR_MULT_DOSStub_540c {
  strings:
    $key_540c = { 00 64 [2] 74 7c [2] 33 7e [2] 74 6f [2] 3a 63 [2] 36 69 [2] 21 62 [2] 3a 2c [2] 07 }

  condition:
    any of them
}