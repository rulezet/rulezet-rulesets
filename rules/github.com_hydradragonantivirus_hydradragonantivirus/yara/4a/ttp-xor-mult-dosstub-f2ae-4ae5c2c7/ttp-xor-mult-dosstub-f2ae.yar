rule TTP_XOR_MULT_DOSStub_f2ae {
  strings:
    $key_f2ae = { a6 c6 [2] d2 de [2] 95 dc [2] d2 cd [2] 9c c1 [2] 90 cb [2] 87 c0 [2] 9c 8e [2] a1 }

  condition:
    any of them
}