rule TTP_XOR_MULT_DOSStub_a8b4 {
  strings:
    $key_a8b4 = { fc dc [2] 88 c4 [2] cf c6 [2] 88 d7 [2] c6 db [2] ca d1 [2] dd da [2] c6 94 [2] fb }

  condition:
    any of them
}