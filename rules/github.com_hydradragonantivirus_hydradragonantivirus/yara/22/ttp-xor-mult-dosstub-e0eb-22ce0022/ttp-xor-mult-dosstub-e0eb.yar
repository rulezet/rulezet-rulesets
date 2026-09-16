rule TTP_XOR_MULT_DOSStub_e0eb {
  strings:
    $key_e0eb = { b4 83 [2] c0 9b [2] 87 99 [2] c0 88 [2] 8e 84 [2] 82 8e [2] 95 85 [2] 8e cb [2] b3 }

  condition:
    any of them
}