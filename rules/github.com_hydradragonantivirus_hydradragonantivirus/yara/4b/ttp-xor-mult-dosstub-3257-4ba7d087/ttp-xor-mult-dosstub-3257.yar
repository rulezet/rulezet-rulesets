rule TTP_XOR_MULT_DOSStub_3257 {
  strings:
    $key_3257 = { 66 3f [2] 12 27 [2] 55 25 [2] 12 34 [2] 5c 38 [2] 50 32 [2] 47 39 [2] 5c 77 [2] 61 }

  condition:
    any of them
}