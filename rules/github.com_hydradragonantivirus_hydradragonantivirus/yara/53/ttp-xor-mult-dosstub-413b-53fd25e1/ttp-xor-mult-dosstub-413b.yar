rule TTP_XOR_MULT_DOSStub_413b {
  strings:
    $key_413b = { 15 53 [2] 61 4b [2] 26 49 [2] 61 58 [2] 2f 54 [2] 23 5e [2] 34 55 [2] 2f 1b [2] 12 }

  condition:
    any of them
}