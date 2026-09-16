rule TTP_XOR_MULT_DOSStub_74fa {
  strings:
    $key_74fa = { 20 92 [2] 54 8a [2] 13 88 [2] 54 99 [2] 1a 95 [2] 16 9f [2] 01 94 [2] 1a da [2] 27 }

  condition:
    any of them
}