rule TTP_XOR_MULT_DOSStub_3ae9 {
  strings:
    $key_3ae9 = { 6e 81 [2] 1a 99 [2] 5d 9b [2] 1a 8a [2] 54 86 [2] 58 8c [2] 4f 87 [2] 54 c9 [2] 69 }

  condition:
    any of them
}