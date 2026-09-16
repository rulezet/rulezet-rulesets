rule TTP_XOR_MULT_DOSStub_49b8 {
  strings:
    $key_49b8 = { 1d d0 [2] 69 c8 [2] 2e ca [2] 69 db [2] 27 d7 [2] 2b dd [2] 3c d6 [2] 27 98 [2] 1a }

  condition:
    any of them
}