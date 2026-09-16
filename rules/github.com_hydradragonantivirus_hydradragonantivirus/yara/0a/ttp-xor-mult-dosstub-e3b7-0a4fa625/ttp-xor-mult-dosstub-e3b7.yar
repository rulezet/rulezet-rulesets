rule TTP_XOR_MULT_DOSStub_e3b7 {
  strings:
    $key_e3b7 = { b7 df [2] c3 c7 [2] 84 c5 [2] c3 d4 [2] 8d d8 [2] 81 d2 [2] 96 d9 [2] 8d 97 [2] b0 }

  condition:
    any of them
}