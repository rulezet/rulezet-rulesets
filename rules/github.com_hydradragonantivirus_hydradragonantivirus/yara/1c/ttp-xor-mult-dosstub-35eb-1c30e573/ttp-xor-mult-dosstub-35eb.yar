rule TTP_XOR_MULT_DOSStub_35eb {
  strings:
    $key_35eb = { 61 83 [2] 15 9b [2] 52 99 [2] 15 88 [2] 5b 84 [2] 57 8e [2] 40 85 [2] 5b cb [2] 66 }

  condition:
    any of them
}