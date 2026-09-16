rule TTP_XOR_MULT_DOSStub_dba7 {
  strings:
    $key_dba7 = { 8f cf [2] fb d7 [2] bc d5 [2] fb c4 [2] b5 c8 [2] b9 c2 [2] ae c9 [2] b5 87 [2] 88 }

  condition:
    any of them
}