rule TTP_XOR_MULT_DOSStub_6ceb {
  strings:
    $key_6ceb = { 38 83 [2] 4c 9b [2] 0b 99 [2] 4c 88 [2] 02 84 [2] 0e 8e [2] 19 85 [2] 02 cb [2] 3f }

  condition:
    any of them
}