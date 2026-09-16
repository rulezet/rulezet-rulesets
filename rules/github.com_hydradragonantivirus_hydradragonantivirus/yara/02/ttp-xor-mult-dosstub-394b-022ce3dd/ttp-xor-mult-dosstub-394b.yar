rule TTP_XOR_MULT_DOSStub_394b {
  strings:
    $key_394b = { 6d 23 [2] 19 3b [2] 5e 39 [2] 19 28 [2] 57 24 [2] 5b 2e [2] 4c 25 [2] 57 6b [2] 6a }

  condition:
    any of them
}