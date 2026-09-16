rule TTP_XOR_MULT_DOSStub_e6eb {
  strings:
    $key_e6eb = { b2 83 [2] c6 9b [2] 81 99 [2] c6 88 [2] 88 84 [2] 84 8e [2] 93 85 [2] 88 cb [2] b5 }

  condition:
    any of them
}