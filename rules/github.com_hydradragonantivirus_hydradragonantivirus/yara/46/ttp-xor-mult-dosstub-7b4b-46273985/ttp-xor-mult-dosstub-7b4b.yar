rule TTP_XOR_MULT_DOSStub_7b4b {
  strings:
    $key_7b4b = { 2f 23 [2] 5b 3b [2] 1c 39 [2] 5b 28 [2] 15 24 [2] 19 2e [2] 0e 25 [2] 15 6b [2] 28 }

  condition:
    any of them
}