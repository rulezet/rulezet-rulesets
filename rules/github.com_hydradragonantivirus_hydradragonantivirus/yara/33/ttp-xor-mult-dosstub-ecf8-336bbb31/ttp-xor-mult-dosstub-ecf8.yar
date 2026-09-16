rule TTP_XOR_MULT_DOSStub_ecf8 {
  strings:
    $key_ecf8 = { b8 90 [2] cc 88 [2] 8b 8a [2] cc 9b [2] 82 97 [2] 8e 9d [2] 99 96 [2] 82 d8 [2] bf }

  condition:
    any of them
}