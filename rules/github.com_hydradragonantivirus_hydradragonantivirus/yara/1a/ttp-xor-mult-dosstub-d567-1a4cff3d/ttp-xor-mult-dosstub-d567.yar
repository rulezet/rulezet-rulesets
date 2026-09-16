rule TTP_XOR_MULT_DOSStub_d567 {
  strings:
    $key_d567 = { 81 0f [2] f5 17 [2] b2 15 [2] f5 04 [2] bb 08 [2] b7 02 [2] a0 09 [2] bb 47 [2] 86 }

  condition:
    any of them
}