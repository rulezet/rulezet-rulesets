rule TTP_XOR_MULT_DOSStub_63eb {
  strings:
    $key_63eb = { 37 83 [2] 43 9b [2] 04 99 [2] 43 88 [2] 0d 84 [2] 01 8e [2] 16 85 [2] 0d cb [2] 30 }

  condition:
    any of them
}