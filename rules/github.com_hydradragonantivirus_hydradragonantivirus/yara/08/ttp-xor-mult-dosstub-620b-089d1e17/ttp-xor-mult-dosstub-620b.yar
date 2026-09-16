rule TTP_XOR_MULT_DOSStub_620b {
  strings:
    $key_620b = { 36 63 [2] 42 7b [2] 05 79 [2] 42 68 [2] 0c 64 [2] 00 6e [2] 17 65 [2] 0c 2b [2] 31 }

  condition:
    any of them
}