rule TTP_XOR_MULT_DOSStub_e0ba {
  strings:
    $key_e0ba = { b4 d2 [2] c0 ca [2] 87 c8 [2] c0 d9 [2] 8e d5 [2] 82 df [2] 95 d4 [2] 8e 9a [2] b3 }

  condition:
    any of them
}