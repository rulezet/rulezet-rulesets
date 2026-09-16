rule TTP_XOR_MULT_DOSStub_1a78 {
  strings:
    $key_1a78 = { 4e 10 [2] 3a 08 [2] 7d 0a [2] 3a 1b [2] 74 17 [2] 78 1d [2] 6f 16 [2] 74 58 [2] 49 }

  condition:
    any of them
}