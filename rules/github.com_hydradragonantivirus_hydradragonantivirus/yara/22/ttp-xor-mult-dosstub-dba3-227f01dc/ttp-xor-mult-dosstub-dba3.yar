rule TTP_XOR_MULT_DOSStub_dba3 {
  strings:
    $key_dba3 = { 8f cb [2] fb d3 [2] bc d1 [2] fb c0 [2] b5 cc [2] b9 c6 [2] ae cd [2] b5 83 [2] 88 }

  condition:
    any of them
}