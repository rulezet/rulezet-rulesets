rule TTP_XOR_MULT_DOSStub_34d9 {
  strings:
    $key_34d9 = { 60 b1 [2] 14 a9 [2] 53 ab [2] 14 ba [2] 5a b6 [2] 56 bc [2] 41 b7 [2] 5a f9 [2] 67 }

  condition:
    any of them
}