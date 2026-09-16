rule TTP_XOR_MULT_DOSStub_d6eb {
  strings:
    $key_d6eb = { 82 83 [2] f6 9b [2] b1 99 [2] f6 88 [2] b8 84 [2] b4 8e [2] a3 85 [2] b8 cb [2] 85 }

  condition:
    any of them
}