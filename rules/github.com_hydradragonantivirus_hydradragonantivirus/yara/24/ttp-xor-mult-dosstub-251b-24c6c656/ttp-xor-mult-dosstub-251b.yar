rule TTP_XOR_MULT_DOSStub_251b {
  strings:
    $key_251b = { 71 73 [2] 05 6b [2] 42 69 [2] 05 78 [2] 4b 74 [2] 47 7e [2] 50 75 [2] 4b 3b [2] 76 }

  condition:
    any of them
}