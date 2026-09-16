rule TTP_XOR_MULT_DOSStub_175b {
  strings:
    $key_175b = { 43 33 [2] 37 2b [2] 70 29 [2] 37 38 [2] 79 34 [2] 75 3e [2] 62 35 [2] 79 7b [2] 44 }

  condition:
    any of them
}