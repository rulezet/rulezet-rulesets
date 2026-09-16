rule TTP_XOR_MULT_DOSStub_02eb {
  strings:
    $key_02eb = { 56 83 [2] 22 9b [2] 65 99 [2] 22 88 [2] 6c 84 [2] 60 8e [2] 77 85 [2] 6c cb [2] 51 }

  condition:
    any of them
}