rule TTP_XOR_MULT_DOSStub_e2ae {
  strings:
    $key_e2ae = { b6 c6 [2] c2 de [2] 85 dc [2] c2 cd [2] 8c c1 [2] 80 cb [2] 97 c0 [2] 8c 8e [2] b1 }

  condition:
    any of them
}