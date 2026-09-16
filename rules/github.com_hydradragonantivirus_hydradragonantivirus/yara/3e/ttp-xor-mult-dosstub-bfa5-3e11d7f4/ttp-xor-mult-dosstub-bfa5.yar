rule TTP_XOR_MULT_DOSStub_bfa5 {
  strings:
    $key_bfa5 = { eb cd [2] 9f d5 [2] d8 d7 [2] 9f c6 [2] d1 ca [2] dd c0 [2] ca cb [2] d1 85 [2] ec }

  condition:
    any of them
}