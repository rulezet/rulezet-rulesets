rule TTP_XOR_MULT_DOSStub_ec17 {
  strings:
    $key_ec17 = { b8 7f [2] cc 67 [2] 8b 65 [2] cc 74 [2] 82 78 [2] 8e 72 [2] 99 79 [2] 82 37 [2] bf }

  condition:
    any of them
}