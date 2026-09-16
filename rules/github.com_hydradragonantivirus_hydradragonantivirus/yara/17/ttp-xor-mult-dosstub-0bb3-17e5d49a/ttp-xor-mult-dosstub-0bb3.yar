rule TTP_XOR_MULT_DOSStub_0bb3 {
  strings:
    $key_0bb3 = { 5f db [2] 2b c3 [2] 6c c1 [2] 2b d0 [2] 65 dc [2] 69 d6 [2] 7e dd [2] 65 93 [2] 58 }

  condition:
    any of them
}