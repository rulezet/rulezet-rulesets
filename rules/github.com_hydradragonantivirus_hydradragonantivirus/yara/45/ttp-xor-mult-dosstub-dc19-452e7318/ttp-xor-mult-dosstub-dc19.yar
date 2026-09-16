rule TTP_XOR_MULT_DOSStub_dc19 {
  strings:
    $key_dc19 = { 88 71 [2] fc 69 [2] bb 6b [2] fc 7a [2] b2 76 [2] be 7c [2] a9 77 [2] b2 39 [2] 8f }

  condition:
    any of them
}