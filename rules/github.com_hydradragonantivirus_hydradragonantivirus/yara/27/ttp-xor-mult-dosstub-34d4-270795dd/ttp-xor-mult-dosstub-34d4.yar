rule TTP_XOR_MULT_DOSStub_34d4 {
  strings:
    $key_34d4 = { 60 bc [2] 14 a4 [2] 53 a6 [2] 14 b7 [2] 5a bb [2] 56 b1 [2] 41 ba [2] 5a f4 [2] 67 }

  condition:
    any of them
}