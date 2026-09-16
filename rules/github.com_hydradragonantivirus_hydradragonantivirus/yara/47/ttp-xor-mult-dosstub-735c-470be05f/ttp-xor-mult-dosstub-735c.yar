rule TTP_XOR_MULT_DOSStub_735c {
  strings:
    $key_735c = { 27 34 [2] 53 2c [2] 14 2e [2] 53 3f [2] 1d 33 [2] 11 39 [2] 06 32 [2] 1d 7c [2] 20 }

  condition:
    any of them
}