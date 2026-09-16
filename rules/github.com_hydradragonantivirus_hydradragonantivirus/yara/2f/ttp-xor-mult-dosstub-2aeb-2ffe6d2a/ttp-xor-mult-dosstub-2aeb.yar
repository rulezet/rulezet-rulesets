rule TTP_XOR_MULT_DOSStub_2aeb {
  strings:
    $key_2aeb = { 7e 83 [2] 0a 9b [2] 4d 99 [2] 0a 88 [2] 44 84 [2] 48 8e [2] 5f 85 [2] 44 cb [2] 79 }

  condition:
    any of them
}