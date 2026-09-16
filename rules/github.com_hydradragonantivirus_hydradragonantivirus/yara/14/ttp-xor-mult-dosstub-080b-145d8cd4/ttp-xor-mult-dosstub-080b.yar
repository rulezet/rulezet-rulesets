rule TTP_XOR_MULT_DOSStub_080b {
  strings:
    $key_080b = { 5c 63 [2] 28 7b [2] 6f 79 [2] 28 68 [2] 66 64 [2] 6a 6e [2] 7d 65 [2] 66 2b [2] 5b }

  condition:
    any of them
}