rule TTP_XOR_MULT_DOSStub_c5b7 {
  strings:
    $key_c5b7 = { 91 df [2] e5 c7 [2] a2 c5 [2] e5 d4 [2] ab d8 [2] a7 d2 [2] b0 d9 [2] ab 97 [2] 96 }

  condition:
    any of them
}