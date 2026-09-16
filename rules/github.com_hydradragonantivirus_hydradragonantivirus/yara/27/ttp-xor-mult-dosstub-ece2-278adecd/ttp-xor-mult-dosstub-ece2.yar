rule TTP_XOR_MULT_DOSStub_ece2 {
  strings:
    $key_ece2 = { b8 8a [2] cc 92 [2] 8b 90 [2] cc 81 [2] 82 8d [2] 8e 87 [2] 99 8c [2] 82 c2 [2] bf }

  condition:
    any of them
}