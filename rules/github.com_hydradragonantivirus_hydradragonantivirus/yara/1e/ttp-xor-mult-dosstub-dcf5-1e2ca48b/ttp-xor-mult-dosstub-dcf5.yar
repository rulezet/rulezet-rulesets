rule TTP_XOR_MULT_DOSStub_dcf5 {
  strings:
    $key_dcf5 = { 88 9d [2] fc 85 [2] bb 87 [2] fc 96 [2] b2 9a [2] be 90 [2] a9 9b [2] b2 d5 [2] 8f }

  condition:
    any of them
}