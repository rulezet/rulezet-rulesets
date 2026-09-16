rule TTP_XOR_MULT_DOSStub_4bb5 {
  strings:
    $key_4bb5 = { 1f dd [2] 6b c5 [2] 2c c7 [2] 6b d6 [2] 25 da [2] 29 d0 [2] 3e db [2] 25 95 [2] 18 }

  condition:
    any of them
}