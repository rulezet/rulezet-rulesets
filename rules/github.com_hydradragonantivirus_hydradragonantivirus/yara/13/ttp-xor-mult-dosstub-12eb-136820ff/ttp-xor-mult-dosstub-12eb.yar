rule TTP_XOR_MULT_DOSStub_12eb {
  strings:
    $key_12eb = { 46 83 [2] 32 9b [2] 75 99 [2] 32 88 [2] 7c 84 [2] 70 8e [2] 67 85 [2] 7c cb [2] 41 }

  condition:
    any of them
}