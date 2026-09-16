rule TTP_XOR_MULT_DOSStub_450b {
  strings:
    $key_450b = { 11 63 [2] 65 7b [2] 22 79 [2] 65 68 [2] 2b 64 [2] 27 6e [2] 30 65 [2] 2b 2b [2] 16 }

  condition:
    any of them
}