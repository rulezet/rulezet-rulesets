rule TTP_XOR_MULT_DOSStub_40eb {
  strings:
    $key_40eb = { 14 83 [2] 60 9b [2] 27 99 [2] 60 88 [2] 2e 84 [2] 22 8e [2] 35 85 [2] 2e cb [2] 13 }

  condition:
    any of them
}