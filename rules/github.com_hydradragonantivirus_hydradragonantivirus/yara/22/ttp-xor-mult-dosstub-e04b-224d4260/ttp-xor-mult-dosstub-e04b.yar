rule TTP_XOR_MULT_DOSStub_e04b {
  strings:
    $key_e04b = { b4 23 [2] c0 3b [2] 87 39 [2] c0 28 [2] 8e 24 [2] 82 2e [2] 95 25 [2] 8e 6b [2] b3 }

  condition:
    any of them
}