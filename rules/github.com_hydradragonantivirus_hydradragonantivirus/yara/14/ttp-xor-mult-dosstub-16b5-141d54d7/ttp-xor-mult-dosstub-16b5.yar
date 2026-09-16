rule TTP_XOR_MULT_DOSStub_16b5 {
  strings:
    $key_16b5 = { 42 dd [2] 36 c5 [2] 71 c7 [2] 36 d6 [2] 78 da [2] 74 d0 [2] 63 db [2] 78 95 [2] 45 }

  condition:
    any of them
}