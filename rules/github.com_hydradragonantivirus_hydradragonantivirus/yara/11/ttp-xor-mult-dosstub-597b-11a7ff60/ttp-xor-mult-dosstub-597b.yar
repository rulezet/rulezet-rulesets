rule TTP_XOR_MULT_DOSStub_597b {
  strings:
    $key_597b = { 0d 13 [2] 79 0b [2] 3e 09 [2] 79 18 [2] 37 14 [2] 3b 1e [2] 2c 15 [2] 37 5b [2] 0a }

  condition:
    any of them
}