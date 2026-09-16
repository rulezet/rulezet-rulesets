rule TTP_XOR_MULT_DOSStub_545c {
  strings:
    $key_545c = { 00 34 [2] 74 2c [2] 33 2e [2] 74 3f [2] 3a 33 [2] 36 39 [2] 21 32 [2] 3a 7c [2] 07 }

  condition:
    any of them
}