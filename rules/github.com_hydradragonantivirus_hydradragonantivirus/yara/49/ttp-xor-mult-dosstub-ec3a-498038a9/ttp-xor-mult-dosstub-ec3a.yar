rule TTP_XOR_MULT_DOSStub_ec3a {
  strings:
    $key_ec3a = { b8 52 [2] cc 4a [2] 8b 48 [2] cc 59 [2] 82 55 [2] 8e 5f [2] 99 54 [2] 82 1a [2] bf }

  condition:
    any of them
}