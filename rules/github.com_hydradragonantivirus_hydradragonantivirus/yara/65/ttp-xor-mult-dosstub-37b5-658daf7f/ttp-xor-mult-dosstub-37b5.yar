rule TTP_XOR_MULT_DOSStub_37b5 {
  strings:
    $key_37b5 = { 63 dd [2] 17 c5 [2] 50 c7 [2] 17 d6 [2] 59 da [2] 55 d0 [2] 42 db [2] 59 95 [2] 64 }

  condition:
    any of them
}