rule TTP_XOR_MULT_DOSStub_4351 {
  strings:
    $key_4351 = { 17 39 [2] 63 21 [2] 24 23 [2] 63 32 [2] 2d 3e [2] 21 34 [2] 36 3f [2] 2d 71 [2] 10 }

  condition:
    any of them
}