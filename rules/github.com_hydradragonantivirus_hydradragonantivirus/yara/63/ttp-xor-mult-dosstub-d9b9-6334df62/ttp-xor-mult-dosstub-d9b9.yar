rule TTP_XOR_MULT_DOSStub_d9b9 {
  strings:
    $key_d9b9 = { 8d d1 [2] f9 c9 [2] be cb [2] f9 da [2] b7 d6 [2] bb dc [2] ac d7 [2] b7 99 [2] 8a }

  condition:
    any of them
}