rule TTP_XOR_MULT_DOSStub_f5ae {
  strings:
    $key_f5ae = { a1 c6 [2] d5 de [2] 92 dc [2] d5 cd [2] 9b c1 [2] 97 cb [2] 80 c0 [2] 9b 8e [2] a6 }

  condition:
    any of them
}