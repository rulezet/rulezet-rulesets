rule TTP_XOR_MULT_DOSStub_313b {
  strings:
    $key_313b = { 65 53 [2] 11 4b [2] 56 49 [2] 11 58 [2] 5f 54 [2] 53 5e [2] 44 55 [2] 5f 1b [2] 62 }

  condition:
    any of them
}