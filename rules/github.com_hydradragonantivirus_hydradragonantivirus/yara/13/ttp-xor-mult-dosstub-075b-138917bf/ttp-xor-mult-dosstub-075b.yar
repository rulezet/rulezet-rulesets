rule TTP_XOR_MULT_DOSStub_075b {
  strings:
    $key_075b = { 53 33 [2] 27 2b [2] 60 29 [2] 27 38 [2] 69 34 [2] 65 3e [2] 72 35 [2] 69 7b [2] 54 }

  condition:
    any of them
}