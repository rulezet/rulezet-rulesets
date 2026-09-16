rule TTP_XOR_MULT_DOSStub_210b {
  strings:
    $key_210b = { 75 63 [2] 01 7b [2] 46 79 [2] 01 68 [2] 4f 64 [2] 43 6e [2] 54 65 [2] 4f 2b [2] 72 }

  condition:
    any of them
}