rule TTP_XOR_MULT_DOSStub_ece7 {
  strings:
    $key_ece7 = { b8 8f [2] cc 97 [2] 8b 95 [2] cc 84 [2] 82 88 [2] 8e 82 [2] 99 89 [2] 82 c7 [2] bf }

  condition:
    any of them
}