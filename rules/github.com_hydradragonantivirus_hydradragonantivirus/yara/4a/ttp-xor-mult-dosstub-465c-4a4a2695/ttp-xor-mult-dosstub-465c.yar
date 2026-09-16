rule TTP_XOR_MULT_DOSStub_465c {
  strings:
    $key_465c = { 12 34 [2] 66 2c [2] 21 2e [2] 66 3f [2] 28 33 [2] 24 39 [2] 33 32 [2] 28 7c [2] 15 }

  condition:
    any of them
}