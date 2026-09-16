rule TTP_XOR_MULT_DOSStub_030b {
  strings:
    $key_030b = { 57 63 [2] 23 7b [2] 64 79 [2] 23 68 [2] 6d 64 [2] 61 6e [2] 76 65 [2] 6d 2b [2] 50 }

  condition:
    any of them
}