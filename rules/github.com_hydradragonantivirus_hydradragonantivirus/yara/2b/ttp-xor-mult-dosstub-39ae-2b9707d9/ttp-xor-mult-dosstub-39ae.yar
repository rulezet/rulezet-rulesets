rule TTP_XOR_MULT_DOSStub_39ae {
  strings:
    $key_39ae = { 6d c6 [2] 19 de [2] 5e dc [2] 19 cd [2] 57 c1 [2] 5b cb [2] 4c c0 [2] 57 8e [2] 6a }

  condition:
    any of them
}