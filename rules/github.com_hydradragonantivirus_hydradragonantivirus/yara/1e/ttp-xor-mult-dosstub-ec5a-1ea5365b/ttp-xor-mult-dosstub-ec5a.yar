rule TTP_XOR_MULT_DOSStub_ec5a {
  strings:
    $key_ec5a = { b8 32 [2] cc 2a [2] 8b 28 [2] cc 39 [2] 82 35 [2] 8e 3f [2] 99 34 [2] 82 7a [2] bf }

  condition:
    any of them
}