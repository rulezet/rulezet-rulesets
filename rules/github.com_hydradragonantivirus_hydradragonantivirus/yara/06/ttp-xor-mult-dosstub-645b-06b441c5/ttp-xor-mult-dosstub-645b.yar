rule TTP_XOR_MULT_DOSStub_645b {
  strings:
    $key_645b = { 30 33 [2] 44 2b [2] 03 29 [2] 44 38 [2] 0a 34 [2] 06 3e [2] 11 35 [2] 0a 7b [2] 37 }

  condition:
    any of them
}