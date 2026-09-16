rule TTP_XOR_MULT_DOSStub_6bb3 {
  strings:
    $key_6bb3 = { 3f db [2] 4b c3 [2] 0c c1 [2] 4b d0 [2] 05 dc [2] 09 d6 [2] 1e dd [2] 05 93 [2] 38 }

  condition:
    any of them
}