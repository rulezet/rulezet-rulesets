rule TTP_XOR_MULT_DOSStub_67b8 {
  strings:
    $key_67b8 = { 33 d0 [2] 47 c8 [2] 00 ca [2] 47 db [2] 09 d7 [2] 05 dd [2] 12 d6 [2] 09 98 [2] 34 }

  condition:
    any of them
}