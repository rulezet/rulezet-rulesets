rule TTP_XOR_MULT_DOSStub_18b8 {
  strings:
    $key_18b8 = { 4c d0 [2] 38 c8 [2] 7f ca [2] 38 db [2] 76 d7 [2] 7a dd [2] 6d d6 [2] 76 98 [2] 4b }

  condition:
    any of them
}