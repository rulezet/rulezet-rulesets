rule TTP_XOR_MULT_DOSStub_523b {
  strings:
    $key_523b = { 06 53 [2] 72 4b [2] 35 49 [2] 72 58 [2] 3c 54 [2] 30 5e [2] 27 55 [2] 3c 1b [2] 01 }

  condition:
    any of them
}