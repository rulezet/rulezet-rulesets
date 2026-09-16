rule TTP_XOR_MULT_DOSStub_86af {
  strings:
    $key_86af = { d2 c7 [2] a6 df [2] e1 dd [2] a6 cc [2] e8 c0 [2] e4 ca [2] f3 c1 [2] e8 8f [2] d5 }

  condition:
    any of them
}