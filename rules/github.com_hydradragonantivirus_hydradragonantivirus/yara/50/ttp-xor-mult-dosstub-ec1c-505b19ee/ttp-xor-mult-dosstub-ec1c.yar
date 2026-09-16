rule TTP_XOR_MULT_DOSStub_ec1c {
  strings:
    $key_ec1c = { b8 74 [2] cc 6c [2] 8b 6e [2] cc 7f [2] 82 73 [2] 8e 79 [2] 99 72 [2] 82 3c [2] bf }

  condition:
    any of them
}