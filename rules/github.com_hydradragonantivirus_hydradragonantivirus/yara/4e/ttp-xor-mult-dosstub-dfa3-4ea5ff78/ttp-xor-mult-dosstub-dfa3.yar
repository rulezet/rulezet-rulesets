rule TTP_XOR_MULT_DOSStub_dfa3 {
  strings:
    $key_dfa3 = { 8b cb [2] ff d3 [2] b8 d1 [2] ff c0 [2] b1 cc [2] bd c6 [2] aa cd [2] b1 83 [2] 8c }

  condition:
    any of them
}