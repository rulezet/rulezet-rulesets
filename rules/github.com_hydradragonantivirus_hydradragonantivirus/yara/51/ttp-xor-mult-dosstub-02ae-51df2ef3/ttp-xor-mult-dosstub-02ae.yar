rule TTP_XOR_MULT_DOSStub_02ae {
  strings:
    $key_02ae = { 56 c6 [2] 22 de [2] 65 dc [2] 22 cd [2] 6c c1 [2] 60 cb [2] 77 c0 [2] 6c 8e [2] 51 }

  condition:
    any of them
}