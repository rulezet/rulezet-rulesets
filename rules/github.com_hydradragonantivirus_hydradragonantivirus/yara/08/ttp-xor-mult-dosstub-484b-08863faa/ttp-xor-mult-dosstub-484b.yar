rule TTP_XOR_MULT_DOSStub_484b {
  strings:
    $key_484b = { 1c 23 [2] 68 3b [2] 2f 39 [2] 68 28 [2] 26 24 [2] 2a 2e [2] 3d 25 [2] 26 6b [2] 1b }

  condition:
    any of them
}