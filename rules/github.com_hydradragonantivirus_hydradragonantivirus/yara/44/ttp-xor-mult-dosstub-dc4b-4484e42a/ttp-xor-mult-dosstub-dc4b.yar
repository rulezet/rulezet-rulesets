rule TTP_XOR_MULT_DOSStub_dc4b {
  strings:
    $key_dc4b = { 88 23 [2] fc 3b [2] bb 39 [2] fc 28 [2] b2 24 [2] be 2e [2] a9 25 [2] b2 6b [2] 8f }

  condition:
    any of them
}