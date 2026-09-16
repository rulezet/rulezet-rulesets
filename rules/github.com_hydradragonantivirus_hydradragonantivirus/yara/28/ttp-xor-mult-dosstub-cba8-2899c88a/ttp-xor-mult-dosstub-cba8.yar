rule TTP_XOR_MULT_DOSStub_cba8 {
  strings:
    $key_cba8 = { 9f c0 [2] eb d8 [2] ac da [2] eb cb [2] a5 c7 [2] a9 cd [2] be c6 [2] a5 88 [2] 98 }

  condition:
    any of them
}