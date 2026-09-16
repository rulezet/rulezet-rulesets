rule TTP_XOR_MULT_DOSStub_2daa {
  strings:
    $key_2daa = { 79 c2 [2] 0d da [2] 4a d8 [2] 0d c9 [2] 43 c5 [2] 4f cf [2] 58 c4 [2] 43 8a [2] 7e }

  condition:
    any of them
}