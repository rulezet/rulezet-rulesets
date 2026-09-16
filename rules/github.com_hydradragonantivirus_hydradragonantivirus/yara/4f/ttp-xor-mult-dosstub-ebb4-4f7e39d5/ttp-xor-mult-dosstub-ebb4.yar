rule TTP_XOR_MULT_DOSStub_ebb4 {
  strings:
    $key_ebb4 = { bf dc [2] cb c4 [2] 8c c6 [2] cb d7 [2] 85 db [2] 89 d1 [2] 9e da [2] 85 94 [2] b8 }

  condition:
    any of them
}