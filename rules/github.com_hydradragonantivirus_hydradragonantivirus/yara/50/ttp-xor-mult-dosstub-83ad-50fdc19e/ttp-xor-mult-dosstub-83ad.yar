rule TTP_XOR_MULT_DOSStub_83ad {
  strings:
    $key_83ad = { d7 c5 [2] a3 dd [2] e4 df [2] a3 ce [2] ed c2 [2] e1 c8 [2] f6 c3 [2] ed 8d [2] d0 }

  condition:
    any of them
}