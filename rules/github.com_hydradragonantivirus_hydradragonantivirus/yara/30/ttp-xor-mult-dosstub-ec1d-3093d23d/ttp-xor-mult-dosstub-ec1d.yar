rule TTP_XOR_MULT_DOSStub_ec1d {
  strings:
    $key_ec1d = { b8 75 [2] cc 6d [2] 8b 6f [2] cc 7e [2] 82 72 [2] 8e 78 [2] 99 73 [2] 82 3d [2] bf }

  condition:
    any of them
}