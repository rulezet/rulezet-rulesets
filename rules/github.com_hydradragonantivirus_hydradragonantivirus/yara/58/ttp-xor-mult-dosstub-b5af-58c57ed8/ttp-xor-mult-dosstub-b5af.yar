rule TTP_XOR_MULT_DOSStub_b5af {
  strings:
    $key_b5af = { e1 c7 [2] 95 df [2] d2 dd [2] 95 cc [2] db c0 [2] d7 ca [2] c0 c1 [2] db 8f [2] e6 }

  condition:
    any of them
}