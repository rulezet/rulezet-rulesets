rule TTP_XOR_MULT_DOSStub_201b {
  strings:
    $key_201b = { 74 73 [2] 00 6b [2] 47 69 [2] 00 78 [2] 4e 74 [2] 42 7e [2] 55 75 [2] 4e 3b [2] 73 }

  condition:
    any of them
}