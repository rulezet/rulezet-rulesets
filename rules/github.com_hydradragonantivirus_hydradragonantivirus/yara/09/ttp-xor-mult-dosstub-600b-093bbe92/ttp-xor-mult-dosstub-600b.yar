rule TTP_XOR_MULT_DOSStub_600b {
  strings:
    $key_600b = { 34 63 [2] 40 7b [2] 07 79 [2] 40 68 [2] 0e 64 [2] 02 6e [2] 15 65 [2] 0e 2b [2] 33 }

  condition:
    any of them
}