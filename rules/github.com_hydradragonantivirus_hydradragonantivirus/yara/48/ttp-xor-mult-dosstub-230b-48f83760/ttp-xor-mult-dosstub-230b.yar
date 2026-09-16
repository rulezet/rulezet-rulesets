rule TTP_XOR_MULT_DOSStub_230b {
  strings:
    $key_230b = { 77 63 [2] 03 7b [2] 44 79 [2] 03 68 [2] 4d 64 [2] 41 6e [2] 56 65 [2] 4d 2b [2] 70 }

  condition:
    any of them
}