rule TTP_XOR_MULT_DOSStub_603b {
  strings:
    $key_603b = { 34 53 [2] 40 4b [2] 07 49 [2] 40 58 [2] 0e 54 [2] 02 5e [2] 15 55 [2] 0e 1b [2] 33 }

  condition:
    any of them
}