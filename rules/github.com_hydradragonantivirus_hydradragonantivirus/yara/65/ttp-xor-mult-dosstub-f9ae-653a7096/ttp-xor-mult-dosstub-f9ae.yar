rule TTP_XOR_MULT_DOSStub_f9ae {
  strings:
    $key_f9ae = { ad c6 [2] d9 de [2] 9e dc [2] d9 cd [2] 97 c1 [2] 9b cb [2] 8c c0 [2] 97 8e [2] aa }

  condition:
    any of them
}