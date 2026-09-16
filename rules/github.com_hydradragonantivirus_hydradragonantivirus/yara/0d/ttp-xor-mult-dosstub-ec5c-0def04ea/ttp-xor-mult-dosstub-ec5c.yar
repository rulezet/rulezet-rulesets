rule TTP_XOR_MULT_DOSStub_ec5c {
  strings:
    $key_ec5c = { b8 34 [2] cc 2c [2] 8b 2e [2] cc 3f [2] 82 33 [2] 8e 39 [2] 99 32 [2] 82 7c [2] bf }

  condition:
    any of them
}