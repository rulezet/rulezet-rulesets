rule TTP_XOR_MULT_DOSStub_0dae {
  strings:
    $key_0dae = { 59 c6 [2] 2d de [2] 6a dc [2] 2d cd [2] 63 c1 [2] 6f cb [2] 78 c0 [2] 63 8e [2] 5e }

  condition:
    any of them
}