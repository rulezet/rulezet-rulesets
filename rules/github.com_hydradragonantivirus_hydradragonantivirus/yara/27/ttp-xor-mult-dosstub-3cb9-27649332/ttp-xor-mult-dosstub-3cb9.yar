rule TTP_XOR_MULT_DOSStub_3cb9 {
  strings:
    $key_3cb9 = { 68 d1 [2] 1c c9 [2] 5b cb [2] 1c da [2] 52 d6 [2] 5e dc [2] 49 d7 [2] 52 99 [2] 6f }

  condition:
    any of them
}