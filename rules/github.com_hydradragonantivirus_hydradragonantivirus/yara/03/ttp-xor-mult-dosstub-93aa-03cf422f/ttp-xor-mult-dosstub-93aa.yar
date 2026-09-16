rule TTP_XOR_MULT_DOSStub_93aa {
  strings:
    $key_93aa = { c7 c2 [2] b3 da [2] f4 d8 [2] b3 c9 [2] fd c5 [2] f1 cf [2] e6 c4 [2] fd 8a [2] c0 }

  condition:
    any of them
}