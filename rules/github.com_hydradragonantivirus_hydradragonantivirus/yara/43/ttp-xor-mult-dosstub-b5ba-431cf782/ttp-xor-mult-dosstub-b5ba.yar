rule TTP_XOR_MULT_DOSStub_b5ba {
  strings:
    $key_b5ba = { e1 d2 [2] 95 ca [2] d2 c8 [2] 95 d9 [2] db d5 [2] d7 df [2] c0 d4 [2] db 9a [2] e6 }

  condition:
    any of them
}