rule TTP_XOR_MULT_DOSStub_3591 {
  strings:
    $key_3591 = { 61 f9 [2] 15 e1 [2] 52 e3 [2] 15 f2 [2] 5b fe [2] 57 f4 [2] 40 ff [2] 5b b1 [2] 66 }

  condition:
    any of them
}