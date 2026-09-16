rule TTP_XOR_MULT_DOSStub_d8ae {
  strings:
    $key_d8ae = { 8c c6 [2] f8 de [2] bf dc [2] f8 cd [2] b6 c1 [2] ba cb [2] ad c0 [2] b6 8e [2] 8b }

  condition:
    any of them
}