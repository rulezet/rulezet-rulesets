rule TTP_XOR_MULT_DOSStub_e1eb {
  strings:
    $key_e1eb = { b5 83 [2] c1 9b [2] 86 99 [2] c1 88 [2] 8f 84 [2] 83 8e [2] 94 85 [2] 8f cb [2] b2 }

  condition:
    any of them
}