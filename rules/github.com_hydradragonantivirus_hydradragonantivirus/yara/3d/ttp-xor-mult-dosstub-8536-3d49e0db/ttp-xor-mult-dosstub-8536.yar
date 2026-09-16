rule TTP_XOR_MULT_DOSStub_8536 {
  strings:
    $key_8536 = { d1 5e [2] a5 46 [2] e2 44 [2] a5 55 [2] eb 59 [2] e7 53 [2] f0 58 [2] eb 16 [2] d6 }

  condition:
    any of them
}