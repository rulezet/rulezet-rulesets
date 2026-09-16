rule TTP_XOR_MULT_DOSStub_17ae {
  strings:
    $key_17ae = { 43 c6 [2] 37 de [2] 70 dc [2] 37 cd [2] 79 c1 [2] 75 cb [2] 62 c0 [2] 79 8e [2] 44 }

  condition:
    any of them
}