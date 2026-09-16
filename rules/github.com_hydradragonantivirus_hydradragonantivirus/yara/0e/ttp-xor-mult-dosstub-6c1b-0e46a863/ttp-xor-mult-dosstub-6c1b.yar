rule TTP_XOR_MULT_DOSStub_6c1b {
  strings:
    $key_6c1b = { 38 73 [2] 4c 6b [2] 0b 69 [2] 4c 78 [2] 02 74 [2] 0e 7e [2] 19 75 [2] 02 3b [2] 3f }

  condition:
    any of them
}