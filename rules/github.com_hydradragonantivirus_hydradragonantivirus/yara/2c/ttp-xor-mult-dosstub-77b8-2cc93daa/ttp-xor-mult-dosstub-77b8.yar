rule TTP_XOR_MULT_DOSStub_77b8 {
  strings:
    $key_77b8 = { 23 d0 [2] 57 c8 [2] 10 ca [2] 57 db [2] 19 d7 [2] 15 dd [2] 02 d6 [2] 19 98 [2] 24 }

  condition:
    any of them
}