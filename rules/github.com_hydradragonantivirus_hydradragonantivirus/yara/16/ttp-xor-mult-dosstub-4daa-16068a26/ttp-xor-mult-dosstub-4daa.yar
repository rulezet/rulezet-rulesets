rule TTP_XOR_MULT_DOSStub_4daa {
  strings:
    $key_4daa = { 19 c2 [2] 6d da [2] 2a d8 [2] 6d c9 [2] 23 c5 [2] 2f cf [2] 38 c4 [2] 23 8a [2] 1e }

  condition:
    any of them
}