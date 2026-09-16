rule TTP_XOR_MULT_DOSStub_7ab4 {
  strings:
    $key_7ab4 = { 2e dc [2] 5a c4 [2] 1d c6 [2] 5a d7 [2] 14 db [2] 18 d1 [2] 0f da [2] 14 94 [2] 29 }

  condition:
    any of them
}