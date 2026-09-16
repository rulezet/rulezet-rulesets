rule TTP_XOR_MULT_DOSStub_2dae {
  strings:
    $key_2dae = { 79 c6 [2] 0d de [2] 4a dc [2] 0d cd [2] 43 c1 [2] 4f cb [2] 58 c0 [2] 43 8e [2] 7e }

  condition:
    any of them
}