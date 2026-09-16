rule TTP_XOR_MULT_DOSStub_4c3b {
  strings:
    $key_4c3b = { 18 53 [2] 6c 4b [2] 2b 49 [2] 6c 58 [2] 22 54 [2] 2e 5e [2] 39 55 [2] 22 1b [2] 1f }

  condition:
    any of them
}