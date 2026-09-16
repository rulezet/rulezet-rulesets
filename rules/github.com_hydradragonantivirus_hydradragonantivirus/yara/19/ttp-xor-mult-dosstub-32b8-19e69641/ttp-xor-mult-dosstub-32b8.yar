rule TTP_XOR_MULT_DOSStub_32b8 {
  strings:
    $key_32b8 = { 66 d0 [2] 12 c8 [2] 55 ca [2] 12 db [2] 5c d7 [2] 50 dd [2] 47 d6 [2] 5c 98 [2] 61 }

  condition:
    any of them
}