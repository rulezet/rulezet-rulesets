rule TTP_XOR_MULT_DOSStub_09b8 {
  strings:
    $key_09b8 = { 5d d0 [2] 29 c8 [2] 6e ca [2] 29 db [2] 67 d7 [2] 6b dd [2] 7c d6 [2] 67 98 [2] 5a }

  condition:
    any of them
}