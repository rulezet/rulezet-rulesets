rule TTP_XOR_MULT_DOSStub_44b8 {
  strings:
    $key_44b8 = { 10 d0 [2] 64 c8 [2] 23 ca [2] 64 db [2] 2a d7 [2] 26 dd [2] 31 d6 [2] 2a 98 [2] 17 }

  condition:
    any of them
}