rule TTP_XOR_MULT_DOSStub_dcf3 {
  strings:
    $key_dcf3 = { 88 9b [2] fc 83 [2] bb 81 [2] fc 90 [2] b2 9c [2] be 96 [2] a9 9d [2] b2 d3 [2] 8f }

  condition:
    any of them
}