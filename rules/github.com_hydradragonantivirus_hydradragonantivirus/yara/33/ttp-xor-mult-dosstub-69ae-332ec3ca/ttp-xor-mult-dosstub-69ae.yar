rule TTP_XOR_MULT_DOSStub_69ae {
  strings:
    $key_69ae = { 3d c6 [2] 49 de [2] 0e dc [2] 49 cd [2] 07 c1 [2] 0b cb [2] 1c c0 [2] 07 8e [2] 3a }

  condition:
    any of them
}