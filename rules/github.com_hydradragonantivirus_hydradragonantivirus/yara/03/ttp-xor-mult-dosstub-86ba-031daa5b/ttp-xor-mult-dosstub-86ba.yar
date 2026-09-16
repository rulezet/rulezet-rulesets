rule TTP_XOR_MULT_DOSStub_86ba {
  strings:
    $key_86ba = { d2 d2 [2] a6 ca [2] e1 c8 [2] a6 d9 [2] e8 d5 [2] e4 df [2] f3 d4 [2] e8 9a [2] d5 }

  condition:
    any of them
}