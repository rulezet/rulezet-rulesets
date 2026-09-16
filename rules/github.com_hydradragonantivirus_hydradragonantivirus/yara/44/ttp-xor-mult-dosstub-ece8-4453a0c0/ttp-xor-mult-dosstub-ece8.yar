rule TTP_XOR_MULT_DOSStub_ece8 {
  strings:
    $key_ece8 = { b8 80 [2] cc 98 [2] 8b 9a [2] cc 8b [2] 82 87 [2] 8e 8d [2] 99 86 [2] 82 c8 [2] bf }

  condition:
    any of them
}