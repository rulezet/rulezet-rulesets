rule TTP_XOR_MULT_DOSStub_3a08 {
  strings:
    $key_3a08 = { 6e 60 [2] 1a 78 [2] 5d 7a [2] 1a 6b [2] 54 67 [2] 58 6d [2] 4f 66 [2] 54 28 [2] 69 }

  condition:
    any of them
}