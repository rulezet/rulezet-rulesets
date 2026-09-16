rule TTP_XOR_MULT_DOSStub_1daa {
  strings:
    $key_1daa = { 49 c2 [2] 3d da [2] 7a d8 [2] 3d c9 [2] 73 c5 [2] 7f cf [2] 68 c4 [2] 73 8a [2] 4e }

  condition:
    any of them
}