rule TTP_XOR_MULT_DOSStub_4407 {
  strings:
    $key_4407 = { 10 6f [2] 64 77 [2] 23 75 [2] 64 64 [2] 2a 68 [2] 26 62 [2] 31 69 [2] 2a 27 [2] 17 }

  condition:
    any of them
}