rule TTP_XOR_MULT_DOSStub_f0ae {
  strings:
    $key_f0ae = { a4 c6 [2] d0 de [2] 97 dc [2] d0 cd [2] 9e c1 [2] 92 cb [2] 85 c0 [2] 9e 8e [2] a3 }

  condition:
    any of them
}