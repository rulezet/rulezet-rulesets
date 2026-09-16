rule TTP_XOR_MULT_DOSStub_37b8 {
  strings:
    $key_37b8 = { 63 d0 [2] 17 c8 [2] 50 ca [2] 17 db [2] 59 d7 [2] 55 dd [2] 42 d6 [2] 59 98 [2] 64 }

  condition:
    any of them
}