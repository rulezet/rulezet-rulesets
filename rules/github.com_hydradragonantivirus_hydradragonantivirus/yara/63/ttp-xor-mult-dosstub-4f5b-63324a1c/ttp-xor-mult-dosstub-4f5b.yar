rule TTP_XOR_MULT_DOSStub_4f5b {
  strings:
    $key_4f5b = { 1b 33 [2] 6f 2b [2] 28 29 [2] 6f 38 [2] 21 34 [2] 2d 3e [2] 3a 35 [2] 21 7b [2] 1c }

  condition:
    any of them
}