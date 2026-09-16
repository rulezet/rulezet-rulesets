rule TTP_XOR_MULT_DOSStub_e0ae {
  strings:
    $key_e0ae = { b4 c6 [2] c0 de [2] 87 dc [2] c0 cd [2] 8e c1 [2] 82 cb [2] 95 c0 [2] 8e 8e [2] b3 }

  condition:
    any of them
}