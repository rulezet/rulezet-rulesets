rule TTP_XOR_MULT_DOSStub_4aeb {
  strings:
    $key_4aeb = { 1e 83 [2] 6a 9b [2] 2d 99 [2] 6a 88 [2] 24 84 [2] 28 8e [2] 3f 85 [2] 24 cb [2] 19 }

  condition:
    any of them
}