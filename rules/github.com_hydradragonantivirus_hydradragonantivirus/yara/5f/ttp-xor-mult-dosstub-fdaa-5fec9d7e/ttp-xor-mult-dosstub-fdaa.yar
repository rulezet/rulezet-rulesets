rule TTP_XOR_MULT_DOSStub_fdaa {
  strings:
    $key_fdaa = { a9 c2 [2] dd da [2] 9a d8 [2] dd c9 [2] 93 c5 [2] 9f cf [2] 88 c4 [2] 93 8a [2] ae }

  condition:
    any of them
}