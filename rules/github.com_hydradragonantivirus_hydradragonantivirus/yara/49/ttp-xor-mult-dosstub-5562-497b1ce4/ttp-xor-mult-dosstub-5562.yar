rule TTP_XOR_MULT_DOSStub_5562 {
  strings:
    $key_5562 = { 01 0a [2] 75 12 [2] 32 10 [2] 75 01 [2] 3b 0d [2] 37 07 [2] 20 0c [2] 3b 42 [2] 06 }

  condition:
    any of them
}