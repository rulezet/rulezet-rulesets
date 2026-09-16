rule TTP_XOR_MULT_DOSStub_dba4 {
  strings:
    $key_dba4 = { 8f cc [2] fb d4 [2] bc d6 [2] fb c7 [2] b5 cb [2] b9 c1 [2] ae ca [2] b5 84 [2] 88 }

  condition:
    any of them
}