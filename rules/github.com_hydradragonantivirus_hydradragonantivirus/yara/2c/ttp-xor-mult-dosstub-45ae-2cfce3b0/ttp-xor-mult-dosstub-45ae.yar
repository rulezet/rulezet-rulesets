rule TTP_XOR_MULT_DOSStub_45ae {
  strings:
    $key_45ae = { 11 c6 [2] 65 de [2] 22 dc [2] 65 cd [2] 2b c1 [2] 27 cb [2] 30 c0 [2] 2b 8e [2] 16 }

  condition:
    any of them
}