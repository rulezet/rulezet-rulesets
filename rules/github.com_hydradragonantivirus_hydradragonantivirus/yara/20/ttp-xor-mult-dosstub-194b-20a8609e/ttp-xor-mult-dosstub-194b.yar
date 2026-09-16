rule TTP_XOR_MULT_DOSStub_194b {
  strings:
    $key_194b = { 4d 23 [2] 39 3b [2] 7e 39 [2] 39 28 [2] 77 24 [2] 7b 2e [2] 6c 25 [2] 77 6b [2] 4a }

  condition:
    any of them
}