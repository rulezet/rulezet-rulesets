rule TTP_XOR_MULT_DOSStub_b0af {
  strings:
    $key_b0af = { e4 c7 [2] 90 df [2] d7 dd [2] 90 cc [2] de c0 [2] d2 ca [2] c5 c1 [2] de 8f [2] e3 }

  condition:
    any of them
}