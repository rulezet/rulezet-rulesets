rule TTP_XOR_MULT_DOSStub_87ae {
  strings:
    $key_87ae = { d3 c6 [2] a7 de [2] e0 dc [2] a7 cd [2] e9 c1 [2] e5 cb [2] f2 c0 [2] e9 8e [2] d4 }

  condition:
    any of them
}