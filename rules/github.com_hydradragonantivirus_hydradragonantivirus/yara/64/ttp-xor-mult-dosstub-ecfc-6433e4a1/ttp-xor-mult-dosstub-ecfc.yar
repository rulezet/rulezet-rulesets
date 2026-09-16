rule TTP_XOR_MULT_DOSStub_ecfc {
  strings:
    $key_ecfc = { b8 94 [2] cc 8c [2] 8b 8e [2] cc 9f [2] 82 93 [2] 8e 99 [2] 99 92 [2] 82 dc [2] bf }

  condition:
    any of them
}