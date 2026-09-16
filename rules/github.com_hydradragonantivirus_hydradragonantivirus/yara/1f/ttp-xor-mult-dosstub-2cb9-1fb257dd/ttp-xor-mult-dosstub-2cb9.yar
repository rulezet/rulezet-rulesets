rule TTP_XOR_MULT_DOSStub_2cb9 {
  strings:
    $key_2cb9 = { 78 d1 [2] 0c c9 [2] 4b cb [2] 0c da [2] 42 d6 [2] 4e dc [2] 59 d7 [2] 42 99 [2] 7f }

  condition:
    any of them
}