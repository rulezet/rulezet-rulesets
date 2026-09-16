rule TTP_XOR_MULT_DOSStub_ecf3 {
  strings:
    $key_ecf3 = { b8 9b [2] cc 83 [2] 8b 81 [2] cc 90 [2] 82 9c [2] 8e 96 [2] 99 9d [2] 82 d3 [2] bf }

  condition:
    any of them
}