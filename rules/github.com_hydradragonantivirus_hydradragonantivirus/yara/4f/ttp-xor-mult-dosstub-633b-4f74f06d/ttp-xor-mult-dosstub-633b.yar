rule TTP_XOR_MULT_DOSStub_633b {
  strings:
    $key_633b = { 37 53 [2] 43 4b [2] 04 49 [2] 43 58 [2] 0d 54 [2] 01 5e [2] 16 55 [2] 0d 1b [2] 30 }

  condition:
    any of them
}