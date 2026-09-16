rule TTP_XOR_MULT_DOSStub_3ae5 {
  strings:
    $key_3ae5 = { 6e 8d [2] 1a 95 [2] 5d 97 [2] 1a 86 [2] 54 8a [2] 58 80 [2] 4f 8b [2] 54 c5 [2] 69 }

  condition:
    any of them
}