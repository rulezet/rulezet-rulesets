rule TTP_XOR_MULT_DOSStub_6c5c {
  strings:
    $key_6c5c = { 38 34 [2] 4c 2c [2] 0b 2e [2] 4c 3f [2] 02 33 [2] 0e 39 [2] 19 32 [2] 02 7c [2] 3f }

  condition:
    any of them
}