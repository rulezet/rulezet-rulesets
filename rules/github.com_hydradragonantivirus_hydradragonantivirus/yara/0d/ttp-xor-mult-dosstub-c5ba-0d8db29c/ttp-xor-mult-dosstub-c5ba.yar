rule TTP_XOR_MULT_DOSStub_c5ba {
  strings:
    $key_c5ba = { 91 d2 [2] e5 ca [2] a2 c8 [2] e5 d9 [2] ab d5 [2] a7 df [2] b0 d4 [2] ab 9a [2] 96 }

  condition:
    any of them
}