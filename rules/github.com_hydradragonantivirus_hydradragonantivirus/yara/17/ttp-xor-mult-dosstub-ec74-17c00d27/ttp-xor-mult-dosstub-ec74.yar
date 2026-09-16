rule TTP_XOR_MULT_DOSStub_ec74 {
  strings:
    $key_ec74 = { b8 1c [2] cc 04 [2] 8b 06 [2] cc 17 [2] 82 1b [2] 8e 11 [2] 99 1a [2] 82 54 [2] bf }

  condition:
    any of them
}