rule TTP_XOR_MULT_DOSStub_c2b8 {
  strings:
    $key_c2b8 = { 96 d0 [2] e2 c8 [2] a5 ca [2] e2 db [2] ac d7 [2] a0 dd [2] b7 d6 [2] ac 98 [2] 91 }

  condition:
    any of them
}