rule TTP_XOR_MULT_DOSStub_e2ba {
  strings:
    $key_e2ba = { b6 d2 [2] c2 ca [2] 85 c8 [2] c2 d9 [2] 8c d5 [2] 80 df [2] 97 d4 [2] 8c 9a [2] b1 }

  condition:
    any of them
}