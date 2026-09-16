rule TTP_XOR_MULT_DOSStub_1bb2 {
  strings:
    $key_1bb2 = { 4f da [2] 3b c2 [2] 7c c0 [2] 3b d1 [2] 75 dd [2] 79 d7 [2] 6e dc [2] 75 92 [2] 48 }

  condition:
    any of them
}