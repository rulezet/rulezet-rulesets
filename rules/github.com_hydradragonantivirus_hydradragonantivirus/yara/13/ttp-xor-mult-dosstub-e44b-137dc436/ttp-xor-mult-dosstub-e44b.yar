rule TTP_XOR_MULT_DOSStub_e44b {
  strings:
    $key_e44b = { b0 23 [2] c4 3b [2] 83 39 [2] c4 28 [2] 8a 24 [2] 86 2e [2] 91 25 [2] 8a 6b [2] b7 }

  condition:
    any of them
}