rule TTP_XOR_MULT_DOSStub_09ae {
  strings:
    $key_09ae = { 5d c6 [2] 29 de [2] 6e dc [2] 29 cd [2] 67 c1 [2] 6b cb [2] 7c c0 [2] 67 8e [2] 5a }

  condition:
    any of them
}