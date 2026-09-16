rule TTP_XOR_MULT_DOSStub_7351 {
  strings:
    $key_7351 = { 27 39 [2] 53 21 [2] 14 23 [2] 53 32 [2] 1d 3e [2] 11 34 [2] 06 3f [2] 1d 71 [2] 20 }

  condition:
    any of them
}