rule TTP_XOR_MULT_DOSStub_6c5b {
  strings:
    $key_6c5b = { 38 33 [2] 4c 2b [2] 0b 29 [2] 4c 38 [2] 02 34 [2] 0e 3e [2] 19 35 [2] 02 7b [2] 3f }

  condition:
    any of them
}