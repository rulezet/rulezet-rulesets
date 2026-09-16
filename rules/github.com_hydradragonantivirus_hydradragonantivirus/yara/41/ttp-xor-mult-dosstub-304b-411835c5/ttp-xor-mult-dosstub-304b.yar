rule TTP_XOR_MULT_DOSStub_304b {
  strings:
    $key_304b = { 64 23 [2] 10 3b [2] 57 39 [2] 10 28 [2] 5e 24 [2] 52 2e [2] 45 25 [2] 5e 6b [2] 63 }

  condition:
    any of them
}