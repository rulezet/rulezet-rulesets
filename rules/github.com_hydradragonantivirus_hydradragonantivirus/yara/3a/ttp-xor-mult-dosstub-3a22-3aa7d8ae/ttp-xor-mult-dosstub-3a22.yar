rule TTP_XOR_MULT_DOSStub_3a22 {
  strings:
    $key_3a22 = { 6e 4a [2] 1a 52 [2] 5d 50 [2] 1a 41 [2] 54 4d [2] 58 47 [2] 4f 4c [2] 54 02 [2] 69 }

  condition:
    any of them
}