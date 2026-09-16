rule TTP_XOR_MULT_DOSStub_24d9 {
  strings:
    $key_24d9 = { 70 b1 [2] 04 a9 [2] 43 ab [2] 04 ba [2] 4a b6 [2] 46 bc [2] 51 b7 [2] 4a f9 [2] 77 }

  condition:
    any of them
}