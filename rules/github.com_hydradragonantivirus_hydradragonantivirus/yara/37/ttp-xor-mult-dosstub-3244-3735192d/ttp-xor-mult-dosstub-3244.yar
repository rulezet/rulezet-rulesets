rule TTP_XOR_MULT_DOSStub_3244 {
  strings:
    $key_3244 = { 66 2c [2] 12 34 [2] 55 36 [2] 12 27 [2] 5c 2b [2] 50 21 [2] 47 2a [2] 5c 64 [2] 61 }

  condition:
    any of them
}