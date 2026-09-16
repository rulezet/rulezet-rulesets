rule TTP_XOR_MULT_DOSStub_5b4b {
  strings:
    $key_5b4b = { 0f 23 [2] 7b 3b [2] 3c 39 [2] 7b 28 [2] 35 24 [2] 39 2e [2] 2e 25 [2] 35 6b [2] 08 }

  condition:
    any of them
}