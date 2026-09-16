rule TTP_XOR_MULT_DOSStub_4214 {
  strings:
    $key_4214 = { 16 7c [2] 62 64 [2] 25 66 [2] 62 77 [2] 2c 7b [2] 20 71 [2] 37 7a [2] 2c 34 [2] 11 }

  condition:
    any of them
}