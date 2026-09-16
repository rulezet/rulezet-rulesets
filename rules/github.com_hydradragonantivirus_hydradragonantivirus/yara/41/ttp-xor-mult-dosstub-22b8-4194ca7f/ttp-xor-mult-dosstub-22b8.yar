rule TTP_XOR_MULT_DOSStub_22b8 {
  strings:
    $key_22b8 = { 76 d0 [2] 02 c8 [2] 45 ca [2] 02 db [2] 4c d7 [2] 40 dd [2] 57 d6 [2] 4c 98 [2] 71 }

  condition:
    any of them
}