rule TTP_XOR_MULT_DOSStub_525b {
  strings:
    $key_525b = { 06 33 [2] 72 2b [2] 35 29 [2] 72 38 [2] 3c 34 [2] 30 3e [2] 27 35 [2] 3c 7b [2] 01 }

  condition:
    any of them
}