rule TTP_XOR_MULT_DOSStub_96af {
  strings:
    $key_96af = { c2 c7 [2] b6 df [2] f1 dd [2] b6 cc [2] f8 c0 [2] f4 ca [2] e3 c1 [2] f8 8f [2] c5 }

  condition:
    any of them
}