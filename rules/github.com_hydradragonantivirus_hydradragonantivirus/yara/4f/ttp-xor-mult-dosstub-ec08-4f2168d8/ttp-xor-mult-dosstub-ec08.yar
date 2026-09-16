rule TTP_XOR_MULT_DOSStub_ec08 {
  strings:
    $key_ec08 = { b8 60 [2] cc 78 [2] 8b 7a [2] cc 6b [2] 82 67 [2] 8e 6d [2] 99 66 [2] 82 28 [2] bf }

  condition:
    any of them
}