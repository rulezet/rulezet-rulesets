rule TTP_XOR_MULT_DOSStub_2257 {
  strings:
    $key_2257 = { 76 3f [2] 02 27 [2] 45 25 [2] 02 34 [2] 4c 38 [2] 40 32 [2] 57 39 [2] 4c 77 [2] 71 }

  condition:
    any of them
}