rule TTP_XOR_MULT_DOSStub_06b5 {
  strings:
    $key_06b5 = { 52 dd [2] 26 c5 [2] 61 c7 [2] 26 d6 [2] 68 da [2] 64 d0 [2] 73 db [2] 68 95 [2] 55 }

  condition:
    any of them
}