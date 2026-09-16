rule TTP_XOR_MULT_DOSStub_22eb {
  strings:
    $key_22eb = { 76 83 [2] 02 9b [2] 45 99 [2] 02 88 [2] 4c 84 [2] 40 8e [2] 57 85 [2] 4c cb [2] 71 }

  condition:
    any of them
}