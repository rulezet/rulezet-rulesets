rule TTP_XOR_MULT_DOSStub_b6ad {
  strings:
    $key_b6ad = { e2 c5 [2] 96 dd [2] d1 df [2] 96 ce [2] d8 c2 [2] d4 c8 [2] c3 c3 [2] d8 8d [2] e5 }

  condition:
    any of them
}