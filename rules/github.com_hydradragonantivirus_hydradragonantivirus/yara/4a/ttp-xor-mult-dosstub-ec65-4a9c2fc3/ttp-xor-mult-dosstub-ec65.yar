rule TTP_XOR_MULT_DOSStub_ec65 {
  strings:
    $key_ec65 = { b8 0d [2] cc 15 [2] 8b 17 [2] cc 06 [2] 82 0a [2] 8e 00 [2] 99 0b [2] 82 45 [2] bf }

  condition:
    any of them
}