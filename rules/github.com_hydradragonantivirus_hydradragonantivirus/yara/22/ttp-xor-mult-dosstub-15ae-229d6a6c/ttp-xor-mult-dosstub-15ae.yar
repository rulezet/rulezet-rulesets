rule TTP_XOR_MULT_DOSStub_15ae {
  strings:
    $key_15ae = { 41 c6 [2] 35 de [2] 72 dc [2] 35 cd [2] 7b c1 [2] 77 cb [2] 60 c0 [2] 7b 8e [2] 46 }

  condition:
    any of them
}