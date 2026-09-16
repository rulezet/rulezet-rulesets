rule TTP_XOR_MULT_DOSStub_0ab4 {
  strings:
    $key_0ab4 = { 5e dc [2] 2a c4 [2] 6d c6 [2] 2a d7 [2] 64 db [2] 68 d1 [2] 7f da [2] 64 94 [2] 59 }

  condition:
    any of them
}