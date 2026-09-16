rule TTP_XOR_MULT_DOSStub_3a28 {
  strings:
    $key_3a28 = { 6e 40 [2] 1a 58 [2] 5d 5a [2] 1a 4b [2] 54 47 [2] 58 4d [2] 4f 46 [2] 54 08 [2] 69 }

  condition:
    any of them
}