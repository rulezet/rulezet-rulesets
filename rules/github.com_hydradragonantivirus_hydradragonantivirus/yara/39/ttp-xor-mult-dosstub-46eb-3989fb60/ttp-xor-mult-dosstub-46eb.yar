rule TTP_XOR_MULT_DOSStub_46eb {
  strings:
    $key_46eb = { 12 83 [2] 66 9b [2] 21 99 [2] 66 88 [2] 28 84 [2] 24 8e [2] 33 85 [2] 28 cb [2] 15 }

  condition:
    any of them
}