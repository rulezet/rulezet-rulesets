rule TTP_XOR_MULT_DOSStub_435c {
  strings:
    $key_435c = { 17 34 [2] 63 2c [2] 24 2e [2] 63 3f [2] 2d 33 [2] 21 39 [2] 36 32 [2] 2d 7c [2] 10 }

  condition:
    any of them
}