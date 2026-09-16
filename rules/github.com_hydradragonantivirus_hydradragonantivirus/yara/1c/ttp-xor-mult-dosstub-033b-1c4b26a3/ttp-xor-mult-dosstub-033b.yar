rule TTP_XOR_MULT_DOSStub_033b {
  strings:
    $key_033b = { 57 53 [2] 23 4b [2] 64 49 [2] 23 58 [2] 6d 54 [2] 61 5e [2] 76 55 [2] 6d 1b [2] 50 }

  condition:
    any of them
}