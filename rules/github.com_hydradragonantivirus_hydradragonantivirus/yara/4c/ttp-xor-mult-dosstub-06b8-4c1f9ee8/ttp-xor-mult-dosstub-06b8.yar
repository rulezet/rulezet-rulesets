rule TTP_XOR_MULT_DOSStub_06b8 {
  strings:
    $key_06b8 = { 52 d0 [2] 26 c8 [2] 61 ca [2] 26 db [2] 68 d7 [2] 64 dd [2] 73 d6 [2] 68 98 [2] 55 }

  condition:
    any of them
}