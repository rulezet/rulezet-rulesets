rule TTP_XOR_MULT_DOSStub_39b8 {
  strings:
    $key_39b8 = { 6d d0 [2] 19 c8 [2] 5e ca [2] 19 db [2] 57 d7 [2] 5b dd [2] 4c d6 [2] 57 98 [2] 6a }

  condition:
    any of them
}