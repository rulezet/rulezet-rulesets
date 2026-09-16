rule TTP_XOR_MULT_DOSStub_465b {
  strings:
    $key_465b = { 12 33 [2] 66 2b [2] 21 29 [2] 66 38 [2] 28 34 [2] 24 3e [2] 33 35 [2] 28 7b [2] 15 }

  condition:
    any of them
}