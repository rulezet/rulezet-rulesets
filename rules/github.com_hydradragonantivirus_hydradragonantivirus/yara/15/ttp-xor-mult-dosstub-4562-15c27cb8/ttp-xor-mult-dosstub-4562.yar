rule TTP_XOR_MULT_DOSStub_4562 {
  strings:
    $key_4562 = { 11 0a [2] 65 12 [2] 22 10 [2] 65 01 [2] 2b 0d [2] 27 07 [2] 30 0c [2] 2b 42 [2] 16 }

  condition:
    any of them
}