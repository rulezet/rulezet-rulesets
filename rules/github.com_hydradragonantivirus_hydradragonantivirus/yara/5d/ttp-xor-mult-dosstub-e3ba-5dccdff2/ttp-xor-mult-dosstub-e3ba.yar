rule TTP_XOR_MULT_DOSStub_e3ba {
  strings:
    $key_e3ba = { b7 d2 [2] c3 ca [2] 84 c8 [2] c3 d9 [2] 8d d5 [2] 81 df [2] 96 d4 [2] 8d 9a [2] b0 }

  condition:
    any of them
}