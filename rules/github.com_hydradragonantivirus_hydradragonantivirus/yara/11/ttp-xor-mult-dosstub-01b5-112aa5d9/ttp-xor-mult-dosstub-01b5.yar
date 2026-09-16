rule TTP_XOR_MULT_DOSStub_01b5 {
  strings:
    $key_01b5 = { 55 dd [2] 21 c5 [2] 66 c7 [2] 21 d6 [2] 6f da [2] 63 d0 [2] 74 db [2] 6f 95 [2] 52 }

  condition:
    any of them
}