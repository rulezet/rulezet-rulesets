rule TTP_XOR_MULT_DOSStub_c3b3 {
  strings:
    $key_c3b3 = { 97 db [2] e3 c3 [2] a4 c1 [2] e3 d0 [2] ad dc [2] a1 d6 [2] b6 dd [2] ad 93 [2] 90 }

  condition:
    any of them
}