rule TTP_XOR_MULT_DOSStub_0a4b {
  strings:
    $key_0a4b = { 5e 23 [2] 2a 3b [2] 6d 39 [2] 2a 28 [2] 64 24 [2] 68 2e [2] 7f 25 [2] 64 6b [2] 59 }

  condition:
    any of them
}