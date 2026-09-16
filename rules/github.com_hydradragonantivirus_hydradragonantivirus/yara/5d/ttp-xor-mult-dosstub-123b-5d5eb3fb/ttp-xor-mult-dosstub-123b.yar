rule TTP_XOR_MULT_DOSStub_123b {
  strings:
    $key_123b = { 46 53 [2] 32 4b [2] 75 49 [2] 32 58 [2] 7c 54 [2] 70 5e [2] 67 55 [2] 7c 1b [2] 41 }

  condition:
    any of them
}