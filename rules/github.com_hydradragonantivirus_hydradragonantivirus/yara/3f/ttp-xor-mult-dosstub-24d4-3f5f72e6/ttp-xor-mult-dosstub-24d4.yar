rule TTP_XOR_MULT_DOSStub_24d4 {
  strings:
    $key_24d4 = { 70 bc [2] 04 a4 [2] 43 a6 [2] 04 b7 [2] 4a bb [2] 46 b1 [2] 51 ba [2] 4a f4 [2] 77 }

  condition:
    any of them
}