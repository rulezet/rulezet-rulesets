rule TTP_XOR_MULT_DOSStub_ecf7 {
  strings:
    $key_ecf7 = { b8 9f [2] cc 87 [2] 8b 85 [2] cc 94 [2] 82 98 [2] 8e 92 [2] 99 99 [2] 82 d7 [2] bf }

  condition:
    any of them
}