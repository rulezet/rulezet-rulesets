rule TTP_XOR_MULT_DOSStub_d7ba {
  strings:
    $key_d7ba = { 83 d2 [2] f7 ca [2] b0 c8 [2] f7 d9 [2] b9 d5 [2] b5 df [2] a2 d4 [2] b9 9a [2] 84 }

  condition:
    any of them
}