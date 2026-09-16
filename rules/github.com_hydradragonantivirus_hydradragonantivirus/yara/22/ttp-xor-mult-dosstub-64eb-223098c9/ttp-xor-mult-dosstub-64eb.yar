rule TTP_XOR_MULT_DOSStub_64eb {
  strings:
    $key_64eb = { 30 83 [2] 44 9b [2] 03 99 [2] 44 88 [2] 0a 84 [2] 06 8e [2] 11 85 [2] 0a cb [2] 37 }

  condition:
    any of them
}