rule TTP_XOR_MULT_DOSStub_31b8 {
  strings:
    $key_31b8 = { 65 d0 [2] 11 c8 [2] 56 ca [2] 11 db [2] 5f d7 [2] 53 dd [2] 44 d6 [2] 5f 98 [2] 62 }

  condition:
    any of them
}