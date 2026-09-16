rule TTP_XOR_MULT_DOSStub_44d9 {
  strings:
    $key_44d9 = { 10 b1 [2] 64 a9 [2] 23 ab [2] 64 ba [2] 2a b6 [2] 26 bc [2] 31 b7 [2] 2a f9 [2] 17 }

  condition:
    any of them
}