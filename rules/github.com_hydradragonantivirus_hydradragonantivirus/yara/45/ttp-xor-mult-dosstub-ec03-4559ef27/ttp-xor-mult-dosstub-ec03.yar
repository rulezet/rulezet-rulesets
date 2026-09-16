rule TTP_XOR_MULT_DOSStub_ec03 {
  strings:
    $key_ec03 = { b8 6b [2] cc 73 [2] 8b 71 [2] cc 60 [2] 82 6c [2] 8e 66 [2] 99 6d [2] 82 23 [2] bf }

  condition:
    any of them
}