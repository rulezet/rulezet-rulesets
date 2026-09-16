rule TTP_XOR_MULT_DOSStub_15eb {
  strings:
    $key_15eb = { 41 83 [2] 35 9b [2] 72 99 [2] 35 88 [2] 7b 84 [2] 77 8e [2] 60 85 [2] 7b cb [2] 46 }

  condition:
    any of them
}