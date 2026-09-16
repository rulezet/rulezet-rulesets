rule TTP_XOR_MULT_DOSStub_640b {
  strings:
    $key_640b = { 30 63 [2] 44 7b [2] 03 79 [2] 44 68 [2] 0a 64 [2] 06 6e [2] 11 65 [2] 0a 2b [2] 37 }

  condition:
    any of them
}