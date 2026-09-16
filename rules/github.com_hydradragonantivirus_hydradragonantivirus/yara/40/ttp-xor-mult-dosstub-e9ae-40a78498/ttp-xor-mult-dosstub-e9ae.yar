rule TTP_XOR_MULT_DOSStub_e9ae {
  strings:
    $key_e9ae = { bd c6 [2] c9 de [2] 8e dc [2] c9 cd [2] 87 c1 [2] 8b cb [2] 9c c0 [2] 87 8e [2] ba }

  condition:
    any of them
}