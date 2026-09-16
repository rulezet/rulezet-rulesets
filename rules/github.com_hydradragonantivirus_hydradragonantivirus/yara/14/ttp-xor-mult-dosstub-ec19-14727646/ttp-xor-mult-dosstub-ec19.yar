rule TTP_XOR_MULT_DOSStub_ec19 {
  strings:
    $key_ec19 = { b8 71 [2] cc 69 [2] 8b 6b [2] cc 7a [2] 82 76 [2] 8e 7c [2] 99 77 [2] 82 39 [2] bf }

  condition:
    any of them
}