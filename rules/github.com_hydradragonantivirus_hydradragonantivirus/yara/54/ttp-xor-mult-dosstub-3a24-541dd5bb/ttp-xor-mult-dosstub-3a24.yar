rule TTP_XOR_MULT_DOSStub_3a24 {
  strings:
    $key_3a24 = { 6e 4c [2] 1a 54 [2] 5d 56 [2] 1a 47 [2] 54 4b [2] 58 41 [2] 4f 4a [2] 54 04 [2] 69 }

  condition:
    any of them
}