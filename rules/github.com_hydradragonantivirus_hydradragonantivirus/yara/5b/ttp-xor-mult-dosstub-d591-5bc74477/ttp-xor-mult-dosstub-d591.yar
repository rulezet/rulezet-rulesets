rule TTP_XOR_MULT_DOSStub_d591 {
  strings:
    $key_d591 = { 81 f9 [2] f5 e1 [2] b2 e3 [2] f5 f2 [2] bb fe [2] b7 f4 [2] a0 ff [2] bb b1 [2] 86 }

  condition:
    any of them
}