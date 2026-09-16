rule TTP_XOR_MULT_DOSStub_6ab4 {
  strings:
    $key_6ab4 = { 3e dc [2] 4a c4 [2] 0d c6 [2] 4a d7 [2] 04 db [2] 08 d1 [2] 1f da [2] 04 94 [2] 39 }

  condition:
    any of them
}