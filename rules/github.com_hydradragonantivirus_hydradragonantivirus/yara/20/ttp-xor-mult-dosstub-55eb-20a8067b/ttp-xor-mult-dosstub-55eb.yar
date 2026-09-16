rule TTP_XOR_MULT_DOSStub_55eb {
  strings:
    $key_55eb = { 01 83 [2] 75 9b [2] 32 99 [2] 75 88 [2] 3b 84 [2] 37 8e [2] 20 85 [2] 3b cb [2] 06 }

  condition:
    any of them
}