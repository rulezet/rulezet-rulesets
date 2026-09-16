rule TTP_XOR_MULT_DOSStub_e5b8 {
  strings:
    $key_e5b8 = { b1 d0 [2] c5 c8 [2] 82 ca [2] c5 db [2] 8b d7 [2] 87 dd [2] 90 d6 [2] 8b 98 [2] b6 }

  condition:
    any of them
}