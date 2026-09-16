rule TTP_XOR_MULT_DOSStub_d9b8 {
  strings:
    $key_d9b8 = { 8d d0 [2] f9 c8 [2] be ca [2] f9 db [2] b7 d7 [2] bb dd [2] ac d6 [2] b7 98 [2] 8a }

  condition:
    any of them
}