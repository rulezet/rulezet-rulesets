rule TTP_XOR_MULT_DOSStub_1244 {
  strings:
    $key_1244 = { 46 2c [2] 32 34 [2] 75 36 [2] 32 27 [2] 7c 2b [2] 70 21 [2] 67 2a [2] 7c 64 [2] 41 }

  condition:
    any of them
}