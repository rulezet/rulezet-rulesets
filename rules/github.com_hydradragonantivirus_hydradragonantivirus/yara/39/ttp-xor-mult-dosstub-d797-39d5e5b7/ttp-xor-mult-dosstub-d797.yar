rule TTP_XOR_MULT_DOSStub_d797 {
  strings:
    $key_d797 = { 83 ff [2] f7 e7 [2] b0 e5 [2] f7 f4 [2] b9 f8 [2] b5 f2 [2] a2 f9 [2] b9 b7 [2] 84 }

  condition:
    any of them
}