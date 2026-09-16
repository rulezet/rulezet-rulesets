rule TTP_XOR_MULT_DOSStub_1a44 {
  strings:
    $key_1a44 = { 4e 2c [2] 3a 34 [2] 7d 36 [2] 3a 27 [2] 74 2b [2] 78 21 [2] 6f 2a [2] 74 64 [2] 49 }

  condition:
    any of them
}