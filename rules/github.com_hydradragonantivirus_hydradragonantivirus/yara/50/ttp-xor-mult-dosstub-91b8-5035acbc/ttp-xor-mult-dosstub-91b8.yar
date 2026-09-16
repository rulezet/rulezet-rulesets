rule TTP_XOR_MULT_DOSStub_91b8 {
  strings:
    $key_91b8 = { c5 d0 [2] b1 c8 [2] f6 ca [2] b1 db [2] ff d7 [2] f3 dd [2] e4 d6 [2] ff 98 [2] c2 }

  condition:
    any of them
}