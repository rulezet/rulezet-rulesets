rule TTP_XOR_MULT_DOSStub_4cb9 {
  strings:
    $key_4cb9 = { 18 d1 [2] 6c c9 [2] 2b cb [2] 6c da [2] 22 d6 [2] 2e dc [2] 39 d7 [2] 22 99 [2] 1f }

  condition:
    any of them
}