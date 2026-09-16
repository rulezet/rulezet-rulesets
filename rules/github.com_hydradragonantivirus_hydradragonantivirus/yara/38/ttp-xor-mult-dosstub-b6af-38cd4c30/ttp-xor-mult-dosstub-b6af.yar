rule TTP_XOR_MULT_DOSStub_b6af {
  strings:
    $key_b6af = { e2 c7 [2] 96 df [2] d1 dd [2] 96 cc [2] d8 c0 [2] d4 ca [2] c3 c1 [2] d8 8f [2] e5 }

  condition:
    any of them
}