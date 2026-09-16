rule TTP_XOR_MULT_DOSStub_e6ba {
  strings:
    $key_e6ba = { b2 d2 [2] c6 ca [2] 81 c8 [2] c6 d9 [2] 88 d5 [2] 84 df [2] 93 d4 [2] 88 9a [2] b5 }

  condition:
    any of them
}