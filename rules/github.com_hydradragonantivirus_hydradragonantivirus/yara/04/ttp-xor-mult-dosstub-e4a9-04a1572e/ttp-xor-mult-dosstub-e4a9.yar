rule TTP_XOR_MULT_DOSStub_e4a9 {
  strings:
    $key_e4a9 = { b0 c1 [2] c4 d9 [2] 83 db [2] c4 ca [2] 8a c6 [2] 86 cc [2] 91 c7 [2] 8a 89 [2] b7 }

  condition:
    any of them
}