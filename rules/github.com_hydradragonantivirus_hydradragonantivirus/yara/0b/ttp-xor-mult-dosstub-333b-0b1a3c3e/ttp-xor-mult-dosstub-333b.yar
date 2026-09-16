rule TTP_XOR_MULT_DOSStub_333b {
  strings:
    $key_333b = { 67 53 [2] 13 4b [2] 54 49 [2] 13 58 [2] 5d 54 [2] 51 5e [2] 46 55 [2] 5d 1b [2] 60 }

  condition:
    any of them
}