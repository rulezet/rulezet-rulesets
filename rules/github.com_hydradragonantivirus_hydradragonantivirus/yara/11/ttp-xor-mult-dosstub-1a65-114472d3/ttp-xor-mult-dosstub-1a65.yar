rule TTP_XOR_MULT_DOSStub_1a65 {
  strings:
    $key_1a65 = { 4e 0d [2] 3a 15 [2] 7d 17 [2] 3a 06 [2] 74 0a [2] 78 00 [2] 6f 0b [2] 74 45 [2] 49 }

  condition:
    any of them
}