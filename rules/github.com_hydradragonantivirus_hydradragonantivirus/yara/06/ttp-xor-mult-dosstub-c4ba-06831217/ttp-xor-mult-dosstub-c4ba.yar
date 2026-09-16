rule TTP_XOR_MULT_DOSStub_c4ba {
  strings:
    $key_c4ba = { 90 d2 [2] e4 ca [2] a3 c8 [2] e4 d9 [2] aa d5 [2] a6 df [2] b1 d4 [2] aa 9a [2] 97 }

  condition:
    any of them
}