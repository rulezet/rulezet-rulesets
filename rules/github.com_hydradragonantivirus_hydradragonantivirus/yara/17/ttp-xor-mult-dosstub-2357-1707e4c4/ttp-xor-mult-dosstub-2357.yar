rule TTP_XOR_MULT_DOSStub_2357 {
  strings:
    $key_2357 = { 77 3f [2] 03 27 [2] 44 25 [2] 03 34 [2] 4d 38 [2] 41 32 [2] 56 39 [2] 4d 77 [2] 70 }

  condition:
    any of them
}