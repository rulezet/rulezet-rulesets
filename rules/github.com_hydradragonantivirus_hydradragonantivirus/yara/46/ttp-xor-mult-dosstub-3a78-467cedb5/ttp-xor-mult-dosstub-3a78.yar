rule TTP_XOR_MULT_DOSStub_3a78 {
  strings:
    $key_3a78 = { 6e 10 [2] 1a 08 [2] 5d 0a [2] 1a 1b [2] 54 17 [2] 58 1d [2] 4f 16 [2] 54 58 [2] 69 }

  condition:
    any of them
}