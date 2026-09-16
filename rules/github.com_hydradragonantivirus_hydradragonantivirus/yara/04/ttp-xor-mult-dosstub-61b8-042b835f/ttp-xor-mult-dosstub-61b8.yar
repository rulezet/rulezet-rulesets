rule TTP_XOR_MULT_DOSStub_61b8 {
  strings:
    $key_61b8 = { 35 d0 [2] 41 c8 [2] 06 ca [2] 41 db [2] 0f d7 [2] 03 dd [2] 14 d6 [2] 0f 98 [2] 32 }

  condition:
    any of them
}