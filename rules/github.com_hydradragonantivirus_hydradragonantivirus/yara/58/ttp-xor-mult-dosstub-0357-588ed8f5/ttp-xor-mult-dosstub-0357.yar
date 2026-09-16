rule TTP_XOR_MULT_DOSStub_0357 {
  strings:
    $key_0357 = { 57 3f [2] 23 27 [2] 64 25 [2] 23 34 [2] 6d 38 [2] 61 32 [2] 76 39 [2] 6d 77 [2] 50 }

  condition:
    any of them
}