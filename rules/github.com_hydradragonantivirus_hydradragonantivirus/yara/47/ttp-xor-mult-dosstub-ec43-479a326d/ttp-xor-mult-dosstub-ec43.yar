rule TTP_XOR_MULT_DOSStub_ec43 {
  strings:
    $key_ec43 = { b8 2b [2] cc 33 [2] 8b 31 [2] cc 20 [2] 82 2c [2] 8e 26 [2] 99 2d [2] 82 63 [2] bf }

  condition:
    any of them
}