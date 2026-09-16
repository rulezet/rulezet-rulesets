rule TTP_XOR_MULT_DOSStub_d791 {
  strings:
    $key_d791 = { 83 f9 [2] f7 e1 [2] b0 e3 [2] f7 f2 [2] b9 fe [2] b5 f4 [2] a2 ff [2] b9 b1 [2] 84 }

  condition:
    any of them
}