rule TTP_XOR_MULT_DOSStub_ec63 {
  strings:
    $key_ec63 = { b8 0b [2] cc 13 [2] 8b 11 [2] cc 00 [2] 82 0c [2] 8e 06 [2] 99 0d [2] 82 43 [2] bf }

  condition:
    any of them
}