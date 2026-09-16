rule TTP_XOR_MULT_DOSStub_daab {
  strings:
    $key_daab = { 8e c3 [2] fa db [2] bd d9 [2] fa c8 [2] b4 c4 [2] b8 ce [2] af c5 [2] b4 8b [2] 89 }

  condition:
    any of them
}