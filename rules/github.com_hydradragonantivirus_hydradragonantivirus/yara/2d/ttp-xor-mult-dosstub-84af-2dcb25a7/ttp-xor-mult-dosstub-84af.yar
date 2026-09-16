rule TTP_XOR_MULT_DOSStub_84af {
  strings:
    $key_84af = { d0 c7 [2] a4 df [2] e3 dd [2] a4 cc [2] ea c0 [2] e6 ca [2] f1 c1 [2] ea 8f [2] d7 }

  condition:
    any of them
}