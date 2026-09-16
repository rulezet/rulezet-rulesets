rule TTP_XOR_MULT_DOSStub_344b {
  strings:
    $key_344b = { 60 23 [2] 14 3b [2] 53 39 [2] 14 28 [2] 5a 24 [2] 56 2e [2] 41 25 [2] 5a 6b [2] 67 }

  condition:
    any of them
}