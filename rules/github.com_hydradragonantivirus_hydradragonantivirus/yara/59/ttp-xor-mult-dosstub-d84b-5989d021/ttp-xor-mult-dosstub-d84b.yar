rule TTP_XOR_MULT_DOSStub_d84b {
  strings:
    $key_d84b = { 8c 23 [2] f8 3b [2] bf 39 [2] f8 28 [2] b6 24 [2] ba 2e [2] ad 25 [2] b6 6b [2] 8b }

  condition:
    any of them
}