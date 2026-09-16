rule TTP_XOR_MULT_DOSStub_dc1b {
  strings:
    $key_dc1b = { 88 73 [2] fc 6b [2] bb 69 [2] fc 78 [2] b2 74 [2] be 7e [2] a9 75 [2] b2 3b [2] 8f }

  condition:
    any of them
}