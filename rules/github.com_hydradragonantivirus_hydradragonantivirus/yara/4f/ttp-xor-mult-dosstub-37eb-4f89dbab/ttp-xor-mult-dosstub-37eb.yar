rule TTP_XOR_MULT_DOSStub_37eb {
  strings:
    $key_37eb = { 63 83 [2] 17 9b [2] 50 99 [2] 17 88 [2] 59 84 [2] 55 8e [2] 42 85 [2] 59 cb [2] 64 }

  condition:
    any of them
}