rule TTP_XOR_MULT_DOSStub_2ceb {
  strings:
    $key_2ceb = { 78 83 [2] 0c 9b [2] 4b 99 [2] 0c 88 [2] 42 84 [2] 4e 8e [2] 59 85 [2] 42 cb [2] 7f }

  condition:
    any of them
}