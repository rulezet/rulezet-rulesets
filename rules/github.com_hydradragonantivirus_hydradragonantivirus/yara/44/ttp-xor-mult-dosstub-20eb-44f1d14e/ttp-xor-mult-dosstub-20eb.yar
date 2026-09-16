rule TTP_XOR_MULT_DOSStub_20eb {
  strings:
    $key_20eb = { 74 83 [2] 00 9b [2] 47 99 [2] 00 88 [2] 4e 84 [2] 42 8e [2] 55 85 [2] 4e cb [2] 73 }

  condition:
    any of them
}