rule TTP_XOR_MULT_DOSStub_3a0b {
  strings:
    $key_3a0b = { 6e 63 [2] 1a 7b [2] 5d 79 [2] 1a 68 [2] 54 64 [2] 58 6e [2] 4f 65 [2] 54 2b [2] 69 }

  condition:
    any of them
}