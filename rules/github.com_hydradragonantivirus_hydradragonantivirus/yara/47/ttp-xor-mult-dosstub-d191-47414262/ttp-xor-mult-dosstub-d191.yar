rule TTP_XOR_MULT_DOSStub_d191 {
  strings:
    $key_d191 = { 85 f9 [2] f1 e1 [2] b6 e3 [2] f1 f2 [2] bf fe [2] b3 f4 [2] a4 ff [2] bf b1 [2] 82 }

  condition:
    any of them
}