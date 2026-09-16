rule TTP_XOR_MULT_DOSStub_ec3f {
  strings:
    $key_ec3f = { b8 57 [2] cc 4f [2] 8b 4d [2] cc 5c [2] 82 50 [2] 8e 5a [2] 99 51 [2] 82 1f [2] bf }

  condition:
    any of them
}