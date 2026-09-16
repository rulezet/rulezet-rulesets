rule TTP_XOR_MULT_DOSStub_d1ae {
  strings:
    $key_d1ae = { 85 c6 [2] f1 de [2] b6 dc [2] f1 cd [2] bf c1 [2] b3 cb [2] a4 c0 [2] bf 8e [2] 82 }

  condition:
    any of them
}