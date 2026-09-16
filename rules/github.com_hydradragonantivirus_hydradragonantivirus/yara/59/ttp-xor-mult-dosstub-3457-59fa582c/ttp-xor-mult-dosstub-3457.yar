rule TTP_XOR_MULT_DOSStub_3457 {
  strings:
    $key_3457 = { 60 3f [2] 14 27 [2] 53 25 [2] 14 34 [2] 5a 38 [2] 56 32 [2] 41 39 [2] 5a 77 [2] 67 }

  condition:
    any of them
}