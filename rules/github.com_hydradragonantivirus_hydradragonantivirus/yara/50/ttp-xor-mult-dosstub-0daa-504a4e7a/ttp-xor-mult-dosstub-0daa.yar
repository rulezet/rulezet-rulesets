rule TTP_XOR_MULT_DOSStub_0daa {
  strings:
    $key_0daa = { 59 c2 [2] 2d da [2] 6a d8 [2] 2d c9 [2] 63 c5 [2] 6f cf [2] 78 c4 [2] 63 8a [2] 5e }

  condition:
    any of them
}