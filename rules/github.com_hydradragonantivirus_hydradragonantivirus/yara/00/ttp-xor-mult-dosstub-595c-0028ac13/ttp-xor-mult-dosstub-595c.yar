rule TTP_XOR_MULT_DOSStub_595c {
  strings:
    $key_595c = { 0d 34 [2] 79 2c [2] 3e 2e [2] 79 3f [2] 37 33 [2] 3b 39 [2] 2c 32 [2] 37 7c [2] 0a }

  condition:
    any of them
}