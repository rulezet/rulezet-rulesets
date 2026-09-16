rule TTP_XOR_MULT_DOSStub_5ceb {
  strings:
    $key_5ceb = { 08 83 [2] 7c 9b [2] 3b 99 [2] 7c 88 [2] 32 84 [2] 3e 8e [2] 29 85 [2] 32 cb [2] 0f }

  condition:
    any of them
}