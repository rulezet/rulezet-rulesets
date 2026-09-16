rule TTP_XOR_MULT_DOSStub_7ea5 {
  strings:
    $key_7ea5 = { 2a cd [2] 5e d5 [2] 19 d7 [2] 5e c6 [2] 10 ca [2] 1c c0 [2] 0b cb [2] 10 85 [2] 2d }

  condition:
    any of them
}