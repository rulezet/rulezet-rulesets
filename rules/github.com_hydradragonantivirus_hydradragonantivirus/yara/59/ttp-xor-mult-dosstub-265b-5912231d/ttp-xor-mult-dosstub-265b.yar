rule TTP_XOR_MULT_DOSStub_265b {
  strings:
    $key_265b = { 72 33 [2] 06 2b [2] 41 29 [2] 06 38 [2] 48 34 [2] 44 3e [2] 53 35 [2] 48 7b [2] 75 }

  condition:
    any of them
}