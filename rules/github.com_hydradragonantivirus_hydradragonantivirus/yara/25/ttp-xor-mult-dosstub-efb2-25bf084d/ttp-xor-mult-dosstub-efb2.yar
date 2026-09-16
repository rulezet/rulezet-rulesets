rule TTP_XOR_MULT_DOSStub_efb2 {
  strings:
    $key_efb2 = { bb da [2] cf c2 [2] 88 c0 [2] cf d1 [2] 81 dd [2] 8d d7 [2] 9a dc [2] 81 92 [2] bc }

  condition:
    any of them
}