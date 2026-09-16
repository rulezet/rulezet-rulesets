rule TTP_XOR_MULT_DOSStub_ec09 {
  strings:
    $key_ec09 = { b8 61 [2] cc 79 [2] 8b 7b [2] cc 6a [2] 82 66 [2] 8e 6c [2] 99 67 [2] 82 29 [2] bf }

  condition:
    any of them
}