rule TTP_XOR_MULT_DOSStub_a4ad {
  strings:
    $key_a4ad = { f0 c5 [2] 84 dd [2] c3 df [2] 84 ce [2] ca c2 [2] c6 c8 [2] d1 c3 [2] ca 8d [2] f7 }

  condition:
    any of them
}