rule TTP_XOR_MULT_DOSStub_5bb3 {
  strings:
    $key_5bb3 = { 0f db [2] 7b c3 [2] 3c c1 [2] 7b d0 [2] 35 dc [2] 39 d6 [2] 2e dd [2] 35 93 [2] 08 }

  condition:
    any of them
}