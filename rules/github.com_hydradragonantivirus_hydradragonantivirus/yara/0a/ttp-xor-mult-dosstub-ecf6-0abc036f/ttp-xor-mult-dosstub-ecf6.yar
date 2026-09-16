rule TTP_XOR_MULT_DOSStub_ecf6 {
  strings:
    $key_ecf6 = { b8 9e [2] cc 86 [2] 8b 84 [2] cc 95 [2] 82 99 [2] 8e 93 [2] 99 98 [2] 82 d6 [2] bf }

  condition:
    any of them
}