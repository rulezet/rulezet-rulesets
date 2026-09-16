rule TTP_XOR_MULT_DOSStub_82bf {
  strings:
    $key_82bf = { d6 d7 [2] a2 cf [2] e5 cd [2] a2 dc [2] ec d0 [2] e0 da [2] f7 d1 [2] ec 9f [2] d1 }

  condition:
    any of them
}