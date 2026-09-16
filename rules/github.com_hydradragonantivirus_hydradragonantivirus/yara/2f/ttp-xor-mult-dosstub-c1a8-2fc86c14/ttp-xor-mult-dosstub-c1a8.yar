rule TTP_XOR_MULT_DOSStub_c1a8 {
  strings:
    $key_c1a8 = { 95 c0 [2] e1 d8 [2] a6 da [2] e1 cb [2] af c7 [2] a3 cd [2] b4 c6 [2] af 88 [2] 92 }

  condition:
    any of them
}