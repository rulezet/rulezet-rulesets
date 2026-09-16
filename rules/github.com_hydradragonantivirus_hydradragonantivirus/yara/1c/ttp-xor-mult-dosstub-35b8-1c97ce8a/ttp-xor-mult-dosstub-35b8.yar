rule TTP_XOR_MULT_DOSStub_35b8 {
  strings:
    $key_35b8 = { 61 d0 [2] 15 c8 [2] 52 ca [2] 15 db [2] 5b d7 [2] 57 dd [2] 40 d6 [2] 5b 98 [2] 66 }

  condition:
    any of them
}