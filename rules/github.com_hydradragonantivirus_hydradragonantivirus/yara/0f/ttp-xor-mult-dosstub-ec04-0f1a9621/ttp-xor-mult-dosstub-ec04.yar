rule TTP_XOR_MULT_DOSStub_ec04 {
  strings:
    $key_ec04 = { b8 6c [2] cc 74 [2] 8b 76 [2] cc 67 [2] 82 6b [2] 8e 61 [2] 99 6a [2] 82 24 [2] bf }

  condition:
    any of them
}