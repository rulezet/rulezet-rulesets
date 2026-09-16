rule TTP_XOR_MULT_DOSStub_baa7 {
  strings:
    $key_baa7 = { ee cf [2] 9a d7 [2] dd d5 [2] 9a c4 [2] d4 c8 [2] d8 c2 [2] cf c9 [2] d4 87 [2] e9 }

  condition:
    any of them
}