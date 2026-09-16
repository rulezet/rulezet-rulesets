rule TTP_XOR_MULT_DOSStub_ec12 {
  strings:
    $key_ec12 = { b8 7a [2] cc 62 [2] 8b 60 [2] cc 71 [2] 82 7d [2] 8e 77 [2] 99 7c [2] 82 32 [2] bf }

  condition:
    any of them
}