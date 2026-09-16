rule TTP_XOR_MULT_DOSStub_3a02 {
  strings:
    $key_3a02 = { 6e 6a [2] 1a 72 [2] 5d 70 [2] 1a 61 [2] 54 6d [2] 58 67 [2] 4f 6c [2] 54 22 [2] 69 }

  condition:
    any of them
}