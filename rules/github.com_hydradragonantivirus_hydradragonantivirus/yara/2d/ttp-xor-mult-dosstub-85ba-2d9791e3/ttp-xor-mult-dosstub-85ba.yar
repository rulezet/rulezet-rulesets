rule TTP_XOR_MULT_DOSStub_85ba {
  strings:
    $key_85ba = { d1 d2 [2] a5 ca [2] e2 c8 [2] a5 d9 [2] eb d5 [2] e7 df [2] f0 d4 [2] eb 9a [2] d6 }

  condition:
    any of them
}