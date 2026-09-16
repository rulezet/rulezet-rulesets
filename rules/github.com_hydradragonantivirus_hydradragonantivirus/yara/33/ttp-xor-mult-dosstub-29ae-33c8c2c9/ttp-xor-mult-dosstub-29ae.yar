rule TTP_XOR_MULT_DOSStub_29ae {
  strings:
    $key_29ae = { 7d c6 [2] 09 de [2] 4e dc [2] 09 cd [2] 47 c1 [2] 4b cb [2] 5c c0 [2] 47 8e [2] 7a }

  condition:
    any of them
}