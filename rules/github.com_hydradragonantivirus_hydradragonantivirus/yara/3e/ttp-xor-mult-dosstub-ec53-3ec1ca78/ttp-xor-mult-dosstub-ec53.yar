rule TTP_XOR_MULT_DOSStub_ec53 {
  strings:
    $key_ec53 = { b8 3b [2] cc 23 [2] 8b 21 [2] cc 30 [2] 82 3c [2] 8e 36 [2] 99 3d [2] 82 73 [2] bf }

  condition:
    any of them
}