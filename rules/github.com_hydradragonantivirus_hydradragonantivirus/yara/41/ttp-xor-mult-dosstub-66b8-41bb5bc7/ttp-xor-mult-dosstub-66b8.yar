rule TTP_XOR_MULT_DOSStub_66b8 {
  strings:
    $key_66b8 = { 32 d0 [2] 46 c8 [2] 01 ca [2] 46 db [2] 08 d7 [2] 04 dd [2] 13 d6 [2] 08 98 [2] 35 }

  condition:
    any of them
}