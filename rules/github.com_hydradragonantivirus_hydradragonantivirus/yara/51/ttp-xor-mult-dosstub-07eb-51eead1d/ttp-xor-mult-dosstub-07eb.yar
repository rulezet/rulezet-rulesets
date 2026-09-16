rule TTP_XOR_MULT_DOSStub_07eb {
  strings:
    $key_07eb = { 53 83 [2] 27 9b [2] 60 99 [2] 27 88 [2] 69 84 [2] 65 8e [2] 72 85 [2] 69 cb [2] 54 }

  condition:
    any of them
}