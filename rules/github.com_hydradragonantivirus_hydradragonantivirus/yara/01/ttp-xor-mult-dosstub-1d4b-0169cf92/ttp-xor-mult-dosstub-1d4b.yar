rule TTP_XOR_MULT_DOSStub_1d4b {
  strings:
    $key_1d4b = { 49 23 [2] 3d 3b [2] 7a 39 [2] 3d 28 [2] 73 24 [2] 7f 2e [2] 68 25 [2] 73 6b [2] 4e }

  condition:
    any of them
}