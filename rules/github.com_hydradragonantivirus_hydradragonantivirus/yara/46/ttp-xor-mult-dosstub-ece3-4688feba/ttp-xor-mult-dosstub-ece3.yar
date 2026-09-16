rule TTP_XOR_MULT_DOSStub_ece3 {
  strings:
    $key_ece3 = { b8 8b [2] cc 93 [2] 8b 91 [2] cc 80 [2] 82 8c [2] 8e 86 [2] 99 8d [2] 82 c3 [2] bf }

  condition:
    any of them
}