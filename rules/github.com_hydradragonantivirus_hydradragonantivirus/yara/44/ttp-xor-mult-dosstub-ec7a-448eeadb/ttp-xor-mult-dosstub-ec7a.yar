rule TTP_XOR_MULT_DOSStub_ec7a {
  strings:
    $key_ec7a = { b8 12 [2] cc 0a [2] 8b 08 [2] cc 19 [2] 82 15 [2] 8e 1f [2] 99 14 [2] 82 5a [2] bf }

  condition:
    any of them
}