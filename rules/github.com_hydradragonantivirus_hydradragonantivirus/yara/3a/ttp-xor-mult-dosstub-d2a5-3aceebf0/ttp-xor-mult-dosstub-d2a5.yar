rule TTP_XOR_MULT_DOSStub_d2a5 {
  strings:
    $key_d2a5 = { 86 cd [2] f2 d5 [2] b5 d7 [2] f2 c6 [2] bc ca [2] b0 c0 [2] a7 cb [2] bc 85 [2] 81 }

  condition:
    any of them
}