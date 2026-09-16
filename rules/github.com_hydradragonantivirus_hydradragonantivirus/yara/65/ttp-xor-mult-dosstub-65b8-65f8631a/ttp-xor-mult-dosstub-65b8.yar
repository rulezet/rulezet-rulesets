rule TTP_XOR_MULT_DOSStub_65b8 {
  strings:
    $key_65b8 = { 31 d0 [2] 45 c8 [2] 02 ca [2] 45 db [2] 0b d7 [2] 07 dd [2] 10 d6 [2] 0b 98 [2] 36 }

  condition:
    any of them
}