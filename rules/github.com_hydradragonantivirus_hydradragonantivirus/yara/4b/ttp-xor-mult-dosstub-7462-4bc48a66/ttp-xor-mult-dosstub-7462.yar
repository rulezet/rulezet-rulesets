rule TTP_XOR_MULT_DOSStub_7462 {
  strings:
    $key_7462 = { 20 0a [2] 54 12 [2] 13 10 [2] 54 01 [2] 1a 0d [2] 16 07 [2] 01 0c [2] 1a 42 [2] 27 }

  condition:
    any of them
}