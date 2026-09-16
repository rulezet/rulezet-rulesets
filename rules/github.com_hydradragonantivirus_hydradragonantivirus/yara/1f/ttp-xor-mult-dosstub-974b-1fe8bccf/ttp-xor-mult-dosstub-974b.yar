rule TTP_XOR_MULT_DOSStub_974b {
  strings:
    $key_974b = { c3 23 [2] b7 3b [2] f0 39 [2] b7 28 [2] f9 24 [2] f5 2e [2] e2 25 [2] f9 6b [2] c4 }

  condition:
    any of them
}