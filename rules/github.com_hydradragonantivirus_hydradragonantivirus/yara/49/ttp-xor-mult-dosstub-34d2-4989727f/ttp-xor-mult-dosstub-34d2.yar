rule TTP_XOR_MULT_DOSStub_34d2 {
  strings:
    $key_34d2 = { 60 ba [2] 14 a2 [2] 53 a0 [2] 14 b1 [2] 5a bd [2] 56 b7 [2] 41 bc [2] 5a f2 [2] 67 }

  condition:
    any of them
}