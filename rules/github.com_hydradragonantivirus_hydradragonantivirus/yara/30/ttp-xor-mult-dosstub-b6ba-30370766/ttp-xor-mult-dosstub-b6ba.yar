rule TTP_XOR_MULT_DOSStub_b6ba {
  strings:
    $key_b6ba = { e2 d2 [2] 96 ca [2] d1 c8 [2] 96 d9 [2] d8 d5 [2] d4 df [2] c3 d4 [2] d8 9a [2] e5 }

  condition:
    any of them
}