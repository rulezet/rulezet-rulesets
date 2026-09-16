rule TTP_XOR_MULT_DOSStub_c1ae {
  strings:
    $key_c1ae = { 95 c6 [2] e1 de [2] a6 dc [2] e1 cd [2] af c1 [2] a3 cb [2] b4 c0 [2] af 8e [2] 92 }

  condition:
    any of them
}