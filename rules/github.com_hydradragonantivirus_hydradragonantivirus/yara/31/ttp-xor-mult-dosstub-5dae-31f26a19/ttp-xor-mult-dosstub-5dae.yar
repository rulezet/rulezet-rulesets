rule TTP_XOR_MULT_DOSStub_5dae {
  strings:
    $key_5dae = { 09 c6 [2] 7d de [2] 3a dc [2] 7d cd [2] 33 c1 [2] 3f cb [2] 28 c0 [2] 33 8e [2] 0e }

  condition:
    any of them
}