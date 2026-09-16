rule TTP_XOR_MULT_DOSStub_7daa {
  strings:
    $key_7daa = { 29 c2 [2] 5d da [2] 1a d8 [2] 5d c9 [2] 13 c5 [2] 1f cf [2] 08 c4 [2] 13 8a [2] 2e }

  condition:
    any of them
}