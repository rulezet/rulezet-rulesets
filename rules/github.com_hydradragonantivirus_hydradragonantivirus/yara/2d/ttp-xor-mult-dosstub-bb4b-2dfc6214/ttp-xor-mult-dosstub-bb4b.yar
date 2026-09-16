rule TTP_XOR_MULT_DOSStub_bb4b {
  strings:
    $key_bb4b = { ef 23 [2] 9b 3b [2] dc 39 [2] 9b 28 [2] d5 24 [2] d9 2e [2] ce 25 [2] d5 6b [2] e8 }

  condition:
    any of them
}