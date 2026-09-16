rule TTP_XOR_MULT_DOSStub_834b {
  strings:
    $key_834b = { d7 23 [2] a3 3b [2] e4 39 [2] a3 28 [2] ed 24 [2] e1 2e [2] f6 25 [2] ed 6b [2] d0 }

  condition:
    any of them
}