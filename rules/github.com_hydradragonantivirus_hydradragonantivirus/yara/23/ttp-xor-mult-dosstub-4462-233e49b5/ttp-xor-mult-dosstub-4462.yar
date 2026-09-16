rule TTP_XOR_MULT_DOSStub_4462 {
  strings:
    $key_4462 = { 10 0a [2] 64 12 [2] 23 10 [2] 64 01 [2] 2a 0d [2] 26 07 [2] 31 0c [2] 2a 42 [2] 17 }

  condition:
    any of them
}