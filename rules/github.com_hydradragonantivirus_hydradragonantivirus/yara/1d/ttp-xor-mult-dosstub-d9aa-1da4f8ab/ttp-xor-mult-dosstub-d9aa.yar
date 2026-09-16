rule TTP_XOR_MULT_DOSStub_d9aa {
  strings:
    $key_d9aa = { 8d c2 [2] f9 da [2] be d8 [2] f9 c9 [2] b7 c5 [2] bb cf [2] ac c4 [2] b7 8a [2] 8a }

  condition:
    any of them
}