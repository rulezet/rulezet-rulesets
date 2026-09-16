rule TTP_XOR_MULT_DOSStub_2497 {
  strings:
    $key_2497 = { 70 ff [2] 04 e7 [2] 43 e5 [2] 04 f4 [2] 4a f8 [2] 46 f2 [2] 51 f9 [2] 4a b7 [2] 77 }

  condition:
    any of them
}