rule TTP_XOR_MULT_DOSStub_29b8 {
  strings:
    $key_29b8 = { 7d d0 [2] 09 c8 [2] 4e ca [2] 09 db [2] 47 d7 [2] 4b dd [2] 5c d6 [2] 47 98 [2] 7a }

  condition:
    any of them
}