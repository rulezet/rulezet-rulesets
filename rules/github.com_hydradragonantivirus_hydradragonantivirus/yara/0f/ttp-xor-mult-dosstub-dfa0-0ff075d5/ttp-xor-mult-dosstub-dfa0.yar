rule TTP_XOR_MULT_DOSStub_dfa0 {
  strings:
    $key_dfa0 = { 8b c8 [2] ff d0 [2] b8 d2 [2] ff c3 [2] b1 cf [2] bd c5 [2] aa ce [2] b1 80 [2] 8c }

  condition:
    any of them
}