rule TTP_XOR_MULT_DOSStub_4532 {
  strings:
    $key_4532 = { 11 5a [2] 65 42 [2] 22 40 [2] 65 51 [2] 2b 5d [2] 27 57 [2] 30 5c [2] 2b 12 [2] 16 }

  condition:
    any of them
}