rule TTP_XOR_MULT_DOSStub_7bb5 {
  strings:
    $key_7bb5 = { 2f dd [2] 5b c5 [2] 1c c7 [2] 5b d6 [2] 15 da [2] 19 d0 [2] 0e db [2] 15 95 [2] 28 }

  condition:
    any of them
}