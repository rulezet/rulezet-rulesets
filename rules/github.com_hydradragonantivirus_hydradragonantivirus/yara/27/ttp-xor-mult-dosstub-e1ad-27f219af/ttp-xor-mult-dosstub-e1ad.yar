rule TTP_XOR_MULT_DOSStub_e1ad {
  strings:
    $key_e1ad = { b5 c5 [2] c1 dd [2] 86 df [2] c1 ce [2] 8f c2 [2] 83 c8 [2] 94 c3 [2] 8f 8d [2] b2 }

  condition:
    any of them
}