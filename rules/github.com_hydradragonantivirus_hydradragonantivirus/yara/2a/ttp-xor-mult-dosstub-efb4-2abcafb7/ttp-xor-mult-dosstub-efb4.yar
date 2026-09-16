rule TTP_XOR_MULT_DOSStub_efb4 {
  strings:
    $key_efb4 = { bb dc [2] cf c4 [2] 88 c6 [2] cf d7 [2] 81 db [2] 8d d1 [2] 9a da [2] 81 94 [2] bc }

  condition:
    any of them
}