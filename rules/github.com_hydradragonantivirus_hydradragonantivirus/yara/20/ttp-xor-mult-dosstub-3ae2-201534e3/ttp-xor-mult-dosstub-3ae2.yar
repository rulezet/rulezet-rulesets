rule TTP_XOR_MULT_DOSStub_3ae2 {
  strings:
    $key_3ae2 = { 6e 8a [2] 1a 92 [2] 5d 90 [2] 1a 81 [2] 54 8d [2] 58 87 [2] 4f 8c [2] 54 c2 [2] 69 }

  condition:
    any of them
}