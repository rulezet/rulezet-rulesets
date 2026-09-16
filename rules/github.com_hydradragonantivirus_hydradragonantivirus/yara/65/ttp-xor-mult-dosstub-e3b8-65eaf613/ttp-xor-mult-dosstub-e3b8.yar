rule TTP_XOR_MULT_DOSStub_e3b8 {
  strings:
    $key_e3b8 = { b7 d0 [2] c3 c8 [2] 84 ca [2] c3 db [2] 8d d7 [2] 81 dd [2] 96 d6 [2] 8d 98 [2] b0 }

  condition:
    any of them
}