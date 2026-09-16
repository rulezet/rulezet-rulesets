rule TTP_XOR_MULT_DOSStub_1f4b {
  strings:
    $key_1f4b = { 4b 23 [2] 3f 3b [2] 78 39 [2] 3f 28 [2] 71 24 [2] 7d 2e [2] 6a 25 [2] 71 6b [2] 4c }

  condition:
    any of them
}