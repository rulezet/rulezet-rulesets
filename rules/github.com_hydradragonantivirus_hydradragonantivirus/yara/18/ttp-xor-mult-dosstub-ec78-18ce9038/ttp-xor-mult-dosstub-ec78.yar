rule TTP_XOR_MULT_DOSStub_ec78 {
  strings:
    $key_ec78 = { b8 10 [2] cc 08 [2] 8b 0a [2] cc 1b [2] 82 17 [2] 8e 1d [2] 99 16 [2] 82 58 [2] bf }

  condition:
    any of them
}