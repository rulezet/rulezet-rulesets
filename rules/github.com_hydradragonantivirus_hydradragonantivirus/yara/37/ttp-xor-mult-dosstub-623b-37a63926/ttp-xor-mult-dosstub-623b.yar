rule TTP_XOR_MULT_DOSStub_623b {
  strings:
    $key_623b = { 36 53 [2] 42 4b [2] 05 49 [2] 42 58 [2] 0c 54 [2] 00 5e [2] 17 55 [2] 0c 1b [2] 31 }

  condition:
    any of them
}