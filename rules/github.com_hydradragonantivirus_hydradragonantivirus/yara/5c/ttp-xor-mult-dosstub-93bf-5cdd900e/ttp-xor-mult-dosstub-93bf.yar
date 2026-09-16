rule TTP_XOR_MULT_DOSStub_93bf {
  strings:
    $key_93bf = { c7 d7 [2] b3 cf [2] f4 cd [2] b3 dc [2] fd d0 [2] f1 da [2] e6 d1 [2] fd 9f [2] c0 }

  condition:
    any of them
}