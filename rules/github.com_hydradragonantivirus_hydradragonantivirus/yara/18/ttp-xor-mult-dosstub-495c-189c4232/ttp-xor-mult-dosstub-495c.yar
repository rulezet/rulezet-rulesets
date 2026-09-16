rule TTP_XOR_MULT_DOSStub_495c {
  strings:
    $key_495c = { 1d 34 [2] 69 2c [2] 2e 2e [2] 69 3f [2] 27 33 [2] 2b 39 [2] 3c 32 [2] 27 7c [2] 1a }

  condition:
    any of them
}