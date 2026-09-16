rule TTP_XOR_MULT_DOSStub_c3b8 {
  strings:
    $key_c3b8 = { 97 d0 [2] e3 c8 [2] a4 ca [2] e3 db [2] ad d7 [2] a1 dd [2] b6 d6 [2] ad 98 [2] 90 }

  condition:
    any of them
}