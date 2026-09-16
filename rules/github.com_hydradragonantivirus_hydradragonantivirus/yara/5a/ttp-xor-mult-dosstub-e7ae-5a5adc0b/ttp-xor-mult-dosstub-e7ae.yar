rule TTP_XOR_MULT_DOSStub_e7ae {
  strings:
    $key_e7ae = { b3 c6 [2] c7 de [2] 80 dc [2] c7 cd [2] 89 c1 [2] 85 cb [2] 92 c0 [2] 89 8e [2] b4 }

  condition:
    any of them
}