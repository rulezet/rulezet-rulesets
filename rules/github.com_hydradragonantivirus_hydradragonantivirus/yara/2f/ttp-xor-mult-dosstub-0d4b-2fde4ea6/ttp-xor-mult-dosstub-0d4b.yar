rule TTP_XOR_MULT_DOSStub_0d4b {
  strings:
    $key_0d4b = { 59 23 [2] 2d 3b [2] 6a 39 [2] 2d 28 [2] 63 24 [2] 6f 2e [2] 78 25 [2] 63 6b [2] 5e }

  condition:
    any of them
}