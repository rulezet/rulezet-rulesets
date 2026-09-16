rule TTP_XOR_MULT_DOSStub_ec52 {
  strings:
    $key_ec52 = { b8 3a [2] cc 22 [2] 8b 20 [2] cc 31 [2] 82 3d [2] 8e 37 [2] 99 3c [2] 82 72 [2] bf }

  condition:
    any of them
}