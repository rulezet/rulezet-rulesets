rule TTP_XOR_MULT_DOSStub_44d2 {
  strings:
    $key_44d2 = { 10 ba [2] 64 a2 [2] 23 a0 [2] 64 b1 [2] 2a bd [2] 26 b7 [2] 31 bc [2] 2a f2 [2] 17 }

  condition:
    any of them
}