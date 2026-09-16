rule TTP_XOR_MULT_DOSStub_d5ba {
  strings:
    $key_d5ba = { 81 d2 [2] f5 ca [2] b2 c8 [2] f5 d9 [2] bb d5 [2] b7 df [2] a0 d4 [2] bb 9a [2] 86 }

  condition:
    any of them
}