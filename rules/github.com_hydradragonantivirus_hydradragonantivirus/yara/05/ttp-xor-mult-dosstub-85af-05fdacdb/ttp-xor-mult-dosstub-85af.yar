rule TTP_XOR_MULT_DOSStub_85af {
  strings:
    $key_85af = { d1 c7 [2] a5 df [2] e2 dd [2] a5 cc [2] eb c0 [2] e7 ca [2] f0 c1 [2] eb 8f [2] d6 }

  condition:
    any of them
}