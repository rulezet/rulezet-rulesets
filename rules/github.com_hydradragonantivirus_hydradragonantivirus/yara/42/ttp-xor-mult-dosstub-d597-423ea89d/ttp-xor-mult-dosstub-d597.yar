rule TTP_XOR_MULT_DOSStub_d597 {
  strings:
    $key_d597 = { 81 ff [2] f5 e7 [2] b2 e5 [2] f5 f4 [2] bb f8 [2] b7 f2 [2] a0 f9 [2] bb b7 [2] 86 }

  condition:
    any of them
}