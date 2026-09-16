rule TTP_XOR_MULT_DOSStub_e5eb {
  strings:
    $key_e5eb = { b1 83 [2] c5 9b [2] 82 99 [2] c5 88 [2] 8b 84 [2] 87 8e [2] 90 85 [2] 8b cb [2] b6 }

  condition:
    any of them
}