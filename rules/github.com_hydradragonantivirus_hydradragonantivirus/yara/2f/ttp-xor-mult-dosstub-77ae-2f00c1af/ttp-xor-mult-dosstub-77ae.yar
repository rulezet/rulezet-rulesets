rule TTP_XOR_MULT_DOSStub_77ae {
  strings:
    $key_77ae = { 23 c6 [2] 57 de [2] 10 dc [2] 57 cd [2] 19 c1 [2] 15 cb [2] 02 c0 [2] 19 8e [2] 24 }

  condition:
    any of them
}