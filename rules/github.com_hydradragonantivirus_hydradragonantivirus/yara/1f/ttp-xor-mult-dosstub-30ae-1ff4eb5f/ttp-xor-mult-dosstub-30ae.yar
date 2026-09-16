rule TTP_XOR_MULT_DOSStub_30ae {
  strings:
    $key_30ae = { 64 c6 [2] 10 de [2] 57 dc [2] 10 cd [2] 5e c1 [2] 52 cb [2] 45 c0 [2] 5e 8e [2] 63 }

  condition:
    any of them
}