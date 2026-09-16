rule TTP_XOR_MULT_DOSStub_b2eb {
  strings:
    $key_b2eb = { e6 83 [2] 92 9b [2] d5 99 [2] 92 88 [2] dc 84 [2] d0 8e [2] c7 85 [2] dc cb [2] e1 }

  condition:
    any of them
}