rule TTP_XOR_MULT_DOSStub_214b {
  strings:
    $key_214b = { 75 23 [2] 01 3b [2] 46 39 [2] 01 28 [2] 4f 24 [2] 43 2e [2] 54 25 [2] 4f 6b [2] 72 }

  condition:
    any of them
}