rule TTP_XOR_MULT_DOSStub_dfa5 {
  strings:
    $key_dfa5 = { 8b cd [2] ff d5 [2] b8 d7 [2] ff c6 [2] b1 ca [2] bd c0 [2] aa cb [2] b1 85 [2] 8c }

  condition:
    any of them
}