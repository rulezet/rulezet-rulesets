rule TTP_XOR_MULT_DOSStub_705b {
  strings:
    $key_705b = { 24 33 [2] 50 2b [2] 17 29 [2] 50 38 [2] 1e 34 [2] 12 3e [2] 05 35 [2] 1e 7b [2] 23 }

  condition:
    any of them
}