rule TTP_XOR_MULT_DOSStub_064b {
  strings:
    $key_064b = { 52 23 [2] 26 3b [2] 61 39 [2] 26 28 [2] 68 24 [2] 64 2e [2] 73 25 [2] 68 6b [2] 55 }

  condition:
    any of them
}