rule TTP_XOR_MULT_DOSStub_dcec {
  strings:
    $key_dcec = { 88 84 [2] fc 9c [2] bb 9e [2] fc 8f [2] b2 83 [2] be 89 [2] a9 82 [2] b2 cc [2] 8f }

  condition:
    any of them
}