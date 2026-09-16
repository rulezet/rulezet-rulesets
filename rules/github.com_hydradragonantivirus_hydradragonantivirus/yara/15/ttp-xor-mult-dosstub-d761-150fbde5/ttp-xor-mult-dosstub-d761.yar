rule TTP_XOR_MULT_DOSStub_d761 {
  strings:
    $key_d761 = { 83 09 [2] f7 11 [2] b0 13 [2] f7 02 [2] b9 0e [2] b5 04 [2] a2 0f [2] b9 41 [2] 84 }

  condition:
    any of them
}