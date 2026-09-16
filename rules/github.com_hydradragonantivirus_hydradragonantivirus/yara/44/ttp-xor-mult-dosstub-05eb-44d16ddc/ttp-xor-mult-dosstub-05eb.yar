rule TTP_XOR_MULT_DOSStub_05eb {
  strings:
    $key_05eb = { 51 83 [2] 25 9b [2] 62 99 [2] 25 88 [2] 6b 84 [2] 67 8e [2] 70 85 [2] 6b cb [2] 56 }

  condition:
    any of them
}