rule TTP_XOR_MULT_DOSStub_10ae {
  strings:
    $key_10ae = { 44 c6 [2] 30 de [2] 77 dc [2] 30 cd [2] 7e c1 [2] 72 cb [2] 65 c0 [2] 7e 8e [2] 43 }

  condition:
    any of them
}