rule TTP_XOR_MULT_DOSStub_55ae {
  strings:
    $key_55ae = { 01 c6 [2] 75 de [2] 32 dc [2] 75 cd [2] 3b c1 [2] 37 cb [2] 20 c0 [2] 3b 8e [2] 06 }

  condition:
    any of them
}