rule TTP_XOR_MULT_DOSStub_ecf1 {
  strings:
    $key_ecf1 = { b8 99 [2] cc 81 [2] 8b 83 [2] cc 92 [2] 82 9e [2] 8e 94 [2] 99 9f [2] 82 d1 [2] bf }

  condition:
    any of them
}