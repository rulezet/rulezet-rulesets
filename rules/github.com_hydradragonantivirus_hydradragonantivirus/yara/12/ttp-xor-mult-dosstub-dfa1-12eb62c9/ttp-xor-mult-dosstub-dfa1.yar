rule TTP_XOR_MULT_DOSStub_dfa1 {
  strings:
    $key_dfa1 = { 8b c9 [2] ff d1 [2] b8 d3 [2] ff c2 [2] b1 ce [2] bd c4 [2] aa cf [2] b1 81 [2] 8c }

  condition:
    any of them
}