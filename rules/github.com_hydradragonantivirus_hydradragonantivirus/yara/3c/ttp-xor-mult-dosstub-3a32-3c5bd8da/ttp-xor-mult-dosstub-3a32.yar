rule TTP_XOR_MULT_DOSStub_3a32 {
  strings:
    $key_3a32 = { 6e 5a [2] 1a 42 [2] 5d 40 [2] 1a 51 [2] 54 5d [2] 58 57 [2] 4f 5c [2] 54 12 [2] 69 }

  condition:
    any of them
}