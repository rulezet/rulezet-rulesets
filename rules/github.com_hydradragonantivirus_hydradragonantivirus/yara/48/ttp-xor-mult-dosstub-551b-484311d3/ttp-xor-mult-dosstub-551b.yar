rule TTP_XOR_MULT_DOSStub_551b {
  strings:
    $key_551b = { 01 73 [2] 75 6b [2] 32 69 [2] 75 78 [2] 3b 74 [2] 37 7e [2] 20 75 [2] 3b 3b [2] 06 }

  condition:
    any of them
}