rule TTP_XOR_MULT_DOSStub_ecf4 {
  strings:
    $key_ecf4 = { b8 9c [2] cc 84 [2] 8b 86 [2] cc 97 [2] 82 9b [2] 8e 91 [2] 99 9a [2] 82 d4 [2] bf }

  condition:
    any of them
}