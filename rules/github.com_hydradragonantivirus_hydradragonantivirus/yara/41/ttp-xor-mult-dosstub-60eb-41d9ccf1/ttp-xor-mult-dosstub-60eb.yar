rule TTP_XOR_MULT_DOSStub_60eb {
  strings:
    $key_60eb = { 34 83 [2] 40 9b [2] 07 99 [2] 40 88 [2] 0e 84 [2] 02 8e [2] 15 85 [2] 0e cb [2] 33 }

  condition:
    any of them
}