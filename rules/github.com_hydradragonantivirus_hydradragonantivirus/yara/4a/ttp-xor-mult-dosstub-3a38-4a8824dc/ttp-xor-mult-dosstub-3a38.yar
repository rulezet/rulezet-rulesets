rule TTP_XOR_MULT_DOSStub_3a38 {
  strings:
    $key_3a38 = { 6e 50 [2] 1a 48 [2] 5d 4a [2] 1a 5b [2] 54 57 [2] 58 5d [2] 4f 56 [2] 54 18 [2] 69 }

  condition:
    any of them
}