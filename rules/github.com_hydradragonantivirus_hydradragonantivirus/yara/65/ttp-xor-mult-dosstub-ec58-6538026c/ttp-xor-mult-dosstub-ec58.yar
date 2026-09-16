rule TTP_XOR_MULT_DOSStub_ec58 {
  strings:
    $key_ec58 = { b8 30 [2] cc 28 [2] 8b 2a [2] cc 3b [2] 82 37 [2] 8e 3d [2] 99 36 [2] 82 78 [2] bf }

  condition:
    any of them
}