rule TTP_XOR_MULT_DOSStub_c6ba {
  strings:
    $key_c6ba = { 92 d2 [2] e6 ca [2] a1 c8 [2] e6 d9 [2] a8 d5 [2] a4 df [2] b3 d4 [2] a8 9a [2] 95 }

  condition:
    any of them
}