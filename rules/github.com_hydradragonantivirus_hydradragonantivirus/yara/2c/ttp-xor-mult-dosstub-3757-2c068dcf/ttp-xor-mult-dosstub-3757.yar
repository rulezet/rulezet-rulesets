rule TTP_XOR_MULT_DOSStub_3757 {
  strings:
    $key_3757 = { 63 3f [2] 17 27 [2] 50 25 [2] 17 34 [2] 59 38 [2] 55 32 [2] 42 39 [2] 59 77 [2] 64 }

  condition:
    any of them
}