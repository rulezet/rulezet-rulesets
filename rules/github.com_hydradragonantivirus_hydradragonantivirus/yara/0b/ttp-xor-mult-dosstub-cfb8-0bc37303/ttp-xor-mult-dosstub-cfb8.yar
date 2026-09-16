rule TTP_XOR_MULT_DOSStub_cfb8 {
  strings:
    $key_cfb8 = { 9b d0 [2] ef c8 [2] a8 ca [2] ef db [2] a1 d7 [2] ad dd [2] ba d6 [2] a1 98 [2] 9c }

  condition:
    any of them
}