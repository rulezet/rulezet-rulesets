rule TTP_XOR_MULT_DOSStub_6ea5 {
  strings:
    $key_6ea5 = { 3a cd [2] 4e d5 [2] 09 d7 [2] 4e c6 [2] 00 ca [2] 0c c0 [2] 1b cb [2] 00 85 [2] 3d }

  condition:
    any of them
}