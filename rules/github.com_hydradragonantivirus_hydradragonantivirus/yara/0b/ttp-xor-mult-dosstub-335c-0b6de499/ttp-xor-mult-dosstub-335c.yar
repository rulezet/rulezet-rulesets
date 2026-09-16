rule TTP_XOR_MULT_DOSStub_335c {
  strings:
    $key_335c = { 67 34 [2] 13 2c [2] 54 2e [2] 13 3f [2] 5d 33 [2] 51 39 [2] 46 32 [2] 5d 7c [2] 60 }

  condition:
    any of them
}