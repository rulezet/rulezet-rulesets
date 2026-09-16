rule TTP_XOR_MULT_DOSStub_87ad {
  strings:
    $key_87ad = { d3 c5 [2] a7 dd [2] e0 df [2] a7 ce [2] e9 c2 [2] e5 c8 [2] f2 c3 [2] e9 8d [2] d4 }

  condition:
    any of them
}