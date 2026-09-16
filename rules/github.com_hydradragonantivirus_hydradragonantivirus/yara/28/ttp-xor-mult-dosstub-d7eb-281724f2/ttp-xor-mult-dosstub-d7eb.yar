rule TTP_XOR_MULT_DOSStub_d7eb {
  strings:
    $key_d7eb = { 83 83 [2] f7 9b [2] b0 99 [2] f7 88 [2] b9 84 [2] b5 8e [2] a2 85 [2] b9 cb [2] 84 }

  condition:
    any of them
}