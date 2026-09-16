rule TTP_XOR_MULT_DOSStub_bbaa {
  strings:
    $key_bbaa = { ef c2 [2] 9b da [2] dc d8 [2] 9b c9 [2] d5 c5 [2] d9 cf [2] ce c4 [2] d5 8a [2] e8 }

  condition:
    any of them
}