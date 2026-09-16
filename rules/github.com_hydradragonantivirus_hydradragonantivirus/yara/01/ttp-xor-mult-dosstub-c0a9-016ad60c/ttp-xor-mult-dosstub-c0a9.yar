rule TTP_XOR_MULT_DOSStub_c0a9 {
  strings:
    $key_c0a9 = { 94 c1 [2] e0 d9 [2] a7 db [2] e0 ca [2] ae c6 [2] a2 cc [2] b5 c7 [2] ae 89 [2] 93 }

  condition:
    any of them
}