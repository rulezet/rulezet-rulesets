rule TTP_XOR_MULT_DOSStub_d8af {
  strings:
    $key_d8af = { 8c c7 [2] f8 df [2] bf dd [2] f8 cc [2] b6 c0 [2] ba ca [2] ad c1 [2] b6 8f [2] 8b }

  condition:
    any of them
}