rule TTP_XOR_MULT_DOSStub_dce1 {
  strings:
    $key_dce1 = { 88 89 [2] fc 91 [2] bb 93 [2] fc 82 [2] b2 8e [2] be 84 [2] a9 8f [2] b2 c1 [2] 8f }

  condition:
    any of them
}