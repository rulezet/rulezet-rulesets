rule TTP_XOR_MULT_DOSStub_3ab4 {
  strings:
    $key_3ab4 = { 6e dc [2] 1a c4 [2] 5d c6 [2] 1a d7 [2] 54 db [2] 58 d1 [2] 4f da [2] 54 94 [2] 69 }

  condition:
    any of them
}