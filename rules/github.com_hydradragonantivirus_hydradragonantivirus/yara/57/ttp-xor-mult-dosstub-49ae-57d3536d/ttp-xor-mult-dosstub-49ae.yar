rule TTP_XOR_MULT_DOSStub_49ae {
  strings:
    $key_49ae = { 1d c6 [2] 69 de [2] 2e dc [2] 69 cd [2] 27 c1 [2] 2b cb [2] 3c c0 [2] 27 8e [2] 1a }

  condition:
    any of them
}