rule TTP_XOR_MULT_DOSStub_70ae {
  strings:
    $key_70ae = { 24 c6 [2] 50 de [2] 17 dc [2] 50 cd [2] 1e c1 [2] 12 cb [2] 05 c0 [2] 1e 8e [2] 23 }

  condition:
    any of them
}