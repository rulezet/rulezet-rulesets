rule TTP_XOR_MULT_DOSStub_82ba {
  strings:
    $key_82ba = { d6 d2 [2] a2 ca [2] e5 c8 [2] a2 d9 [2] ec d5 [2] e0 df [2] f7 d4 [2] ec 9a [2] d1 }

  condition:
    any of them
}