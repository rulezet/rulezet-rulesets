rule TTP_XOR_MULT_DOSStub_c5b3 {
  strings:
    $key_c5b3 = { 91 db [2] e5 c3 [2] a2 c1 [2] e5 d0 [2] ab dc [2] a7 d6 [2] b0 dd [2] ab 93 [2] 96 }

  condition:
    any of them
}