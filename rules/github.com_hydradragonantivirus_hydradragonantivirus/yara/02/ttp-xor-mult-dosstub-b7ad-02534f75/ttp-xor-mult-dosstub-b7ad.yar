rule TTP_XOR_MULT_DOSStub_b7ad {
  strings:
    $key_b7ad = { e3 c5 [2] 97 dd [2] d0 df [2] 97 ce [2] d9 c2 [2] d5 c8 [2] c2 c3 [2] d9 8d [2] e4 }

  condition:
    any of them
}