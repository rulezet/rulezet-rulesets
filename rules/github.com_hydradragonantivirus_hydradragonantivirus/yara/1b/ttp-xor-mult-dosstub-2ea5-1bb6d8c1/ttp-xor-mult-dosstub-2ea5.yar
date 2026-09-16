rule TTP_XOR_MULT_DOSStub_2ea5 {
  strings:
    $key_2ea5 = { 7a cd [2] 0e d5 [2] 49 d7 [2] 0e c6 [2] 40 ca [2] 4c c0 [2] 5b cb [2] 40 85 [2] 7d }

  condition:
    any of them
}