rule TTP_XOR_MULT_DOSStub_67eb {
  strings:
    $key_67eb = { 33 83 [2] 47 9b [2] 00 99 [2] 47 88 [2] 09 84 [2] 05 8e [2] 12 85 [2] 09 cb [2] 34 }

  condition:
    any of them
}