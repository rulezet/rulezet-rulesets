rule TTP_XOR_MULT_DOSStub_4d57 {
  strings:
    $key_4d57 = { 19 3f [2] 6d 27 [2] 2a 25 [2] 6d 34 [2] 23 38 [2] 2f 32 [2] 38 39 [2] 23 77 [2] 1e }

  condition:
    any of them
}