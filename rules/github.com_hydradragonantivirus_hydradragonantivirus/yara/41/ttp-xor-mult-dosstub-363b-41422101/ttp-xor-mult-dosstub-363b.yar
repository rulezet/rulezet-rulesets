rule TTP_XOR_MULT_DOSStub_363b {
  strings:
    $key_363b = { 62 53 [2] 16 4b [2] 51 49 [2] 16 58 [2] 58 54 [2] 54 5e [2] 43 55 [2] 58 1b [2] 65 }

  condition:
    any of them
}