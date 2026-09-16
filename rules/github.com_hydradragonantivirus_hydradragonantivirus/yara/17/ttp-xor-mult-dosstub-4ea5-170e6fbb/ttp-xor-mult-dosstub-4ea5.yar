rule TTP_XOR_MULT_DOSStub_4ea5 {
  strings:
    $key_4ea5 = { 1a cd [2] 6e d5 [2] 29 d7 [2] 6e c6 [2] 20 ca [2] 2c c0 [2] 3b cb [2] 20 85 [2] 1d }

  condition:
    any of them
}