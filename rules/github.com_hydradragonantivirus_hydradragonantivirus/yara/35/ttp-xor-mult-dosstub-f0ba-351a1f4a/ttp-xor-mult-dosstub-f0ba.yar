rule TTP_XOR_MULT_DOSStub_f0ba {
  strings:
    $key_f0ba = { a4 d2 [2] d0 ca [2] 97 c8 [2] d0 d9 [2] 9e d5 [2] 92 df [2] 85 d4 [2] 9e 9a [2] a3 }

  condition:
    any of them
}