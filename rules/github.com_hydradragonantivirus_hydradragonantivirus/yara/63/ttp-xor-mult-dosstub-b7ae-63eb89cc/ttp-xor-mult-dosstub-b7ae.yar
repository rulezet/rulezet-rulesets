rule TTP_XOR_MULT_DOSStub_b7ae {
  strings:
    $key_b7ae = { e3 c6 [2] 97 de [2] d0 dc [2] 97 cd [2] d9 c1 [2] d5 cb [2] c2 c0 [2] d9 8e [2] e4 }

  condition:
    any of them
}