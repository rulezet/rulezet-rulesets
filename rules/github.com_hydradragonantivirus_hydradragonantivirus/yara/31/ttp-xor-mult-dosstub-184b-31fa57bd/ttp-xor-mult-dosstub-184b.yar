rule TTP_XOR_MULT_DOSStub_184b {
  strings:
    $key_184b = { 4c 23 [2] 38 3b [2] 7f 39 [2] 38 28 [2] 76 24 [2] 7a 2e [2] 6d 25 [2] 76 6b [2] 4b }

  condition:
    any of them
}