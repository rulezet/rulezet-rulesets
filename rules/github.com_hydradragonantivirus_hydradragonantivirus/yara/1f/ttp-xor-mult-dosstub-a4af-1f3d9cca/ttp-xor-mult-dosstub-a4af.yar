rule TTP_XOR_MULT_DOSStub_a4af {
  strings:
    $key_a4af = { f0 c7 [2] 84 df [2] c3 dd [2] 84 cc [2] ca c0 [2] c6 ca [2] d1 c1 [2] ca 8f [2] f7 }

  condition:
    any of them
}