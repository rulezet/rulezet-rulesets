rule TTP_XOR_MULT_DOSStub_4415 {
  strings:
    $key_4415 = { 10 7d [2] 64 65 [2] 23 67 [2] 64 76 [2] 2a 7a [2] 26 70 [2] 31 7b [2] 2a 35 [2] 17 }

  condition:
    any of them
}