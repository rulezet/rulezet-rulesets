rule TTP_XOR_MULT_DOSStub_d097 {
  strings:
    $key_d097 = { 84 ff [2] f0 e7 [2] b7 e5 [2] f0 f4 [2] be f8 [2] b2 f2 [2] a5 f9 [2] be b7 [2] 83 }

  condition:
    any of them
}