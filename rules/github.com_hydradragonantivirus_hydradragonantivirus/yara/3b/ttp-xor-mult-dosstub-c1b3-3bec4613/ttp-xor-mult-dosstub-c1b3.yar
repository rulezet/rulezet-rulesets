rule TTP_XOR_MULT_DOSStub_c1b3 {
  strings:
    $key_c1b3 = { 95 db [2] e1 c3 [2] a6 c1 [2] e1 d0 [2] af dc [2] a3 d6 [2] b4 dd [2] af 93 [2] 92 }

  condition:
    any of them
}