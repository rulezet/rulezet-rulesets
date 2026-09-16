rule TTP_XOR_MULT_DOSStub_4bb3 {
  strings:
    $key_4bb3 = { 1f db [2] 6b c3 [2] 2c c1 [2] 6b d0 [2] 25 dc [2] 29 d6 [2] 3e dd [2] 25 93 [2] 18 }

  condition:
    any of them
}