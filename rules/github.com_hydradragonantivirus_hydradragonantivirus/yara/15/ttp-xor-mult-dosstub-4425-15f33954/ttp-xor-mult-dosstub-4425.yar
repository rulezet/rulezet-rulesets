rule TTP_XOR_MULT_DOSStub_4425 {
  strings:
    $key_4425 = { 10 4d [2] 64 55 [2] 23 57 [2] 64 46 [2] 2a 4a [2] 26 40 [2] 31 4b [2] 2a 05 [2] 17 }

  condition:
    any of them
}