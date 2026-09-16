rule TTP_XOR_MULT_DOSStub_dfb4 {
  strings:
    $key_dfb4 = { 8b dc [2] ff c4 [2] b8 c6 [2] ff d7 [2] b1 db [2] bd d1 [2] aa da [2] b1 94 [2] 8c }

  condition:
    any of them
}