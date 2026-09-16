rule TTP_XOR_MULT_DOSStub_e7b8 {
  strings:
    $key_e7b8 = { b3 d0 [2] c7 c8 [2] 80 ca [2] c7 db [2] 89 d7 [2] 85 dd [2] 92 d6 [2] 89 98 [2] b4 }

  condition:
    any of them
}