rule TTP_XOR_MULT_DOSStub_e1ae {
  strings:
    $key_e1ae = { b5 c6 [2] c1 de [2] 86 dc [2] c1 cd [2] 8f c1 [2] 83 cb [2] 94 c0 [2] 8f 8e [2] b2 }

  condition:
    any of them
}