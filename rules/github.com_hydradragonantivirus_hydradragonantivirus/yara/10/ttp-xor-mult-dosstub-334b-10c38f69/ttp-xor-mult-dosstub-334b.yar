rule TTP_XOR_MULT_DOSStub_334b {
  strings:
    $key_334b = { 67 23 [2] 13 3b [2] 54 39 [2] 13 28 [2] 5d 24 [2] 51 2e [2] 46 25 [2] 5d 6b [2] 60 }

  condition:
    any of them
}