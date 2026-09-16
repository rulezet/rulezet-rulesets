rule TTP_XOR_MULT_DOSStub_4ceb {
  strings:
    $key_4ceb = { 18 83 [2] 6c 9b [2] 2b 99 [2] 6c 88 [2] 22 84 [2] 2e 8e [2] 39 85 [2] 22 cb [2] 1f }

  condition:
    any of them
}