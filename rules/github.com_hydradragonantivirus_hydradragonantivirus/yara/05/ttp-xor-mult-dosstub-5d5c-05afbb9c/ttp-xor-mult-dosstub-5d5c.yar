rule TTP_XOR_MULT_DOSStub_5d5c {
  strings:
    $key_5d5c = { 09 34 [2] 7d 2c [2] 3a 2e [2] 7d 3f [2] 33 33 [2] 3f 39 [2] 28 32 [2] 33 7c [2] 0e }

  condition:
    any of them
}