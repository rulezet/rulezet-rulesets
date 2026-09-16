rule TTP_XOR_MULT_DOSStub_ec47 {
  strings:
    $key_ec47 = { b8 2f [2] cc 37 [2] 8b 35 [2] cc 24 [2] 82 28 [2] 8e 22 [2] 99 29 [2] 82 67 [2] bf }

  condition:
    any of them
}