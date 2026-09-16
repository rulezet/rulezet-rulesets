rule TTP_XOR_MULT_DOSStub_043b {
  strings:
    $key_043b = { 50 53 [2] 24 4b [2] 63 49 [2] 24 58 [2] 6a 54 [2] 66 5e [2] 71 55 [2] 6a 1b [2] 57 }

  condition:
    any of them
}