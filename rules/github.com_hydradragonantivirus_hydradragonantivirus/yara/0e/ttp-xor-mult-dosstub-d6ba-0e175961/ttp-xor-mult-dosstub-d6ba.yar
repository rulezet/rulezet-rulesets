rule TTP_XOR_MULT_DOSStub_d6ba {
  strings:
    $key_d6ba = { 82 d2 [2] f6 ca [2] b1 c8 [2] f6 d9 [2] b8 d5 [2] b4 df [2] a3 d4 [2] b8 9a [2] 85 }

  condition:
    any of them
}