rule TTP_XOR_MULT_DOSStub_a2ae {
  strings:
    $key_a2ae = { f6 c6 [2] 82 de [2] c5 dc [2] 82 cd [2] cc c1 [2] c0 cb [2] d7 c0 [2] cc 8e [2] f1 }

  condition:
    any of them
}