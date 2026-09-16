rule TTP_XOR_MULT_DOSStub_dce9 {
  strings:
    $key_dce9 = { 88 81 [2] fc 99 [2] bb 9b [2] fc 8a [2] b2 86 [2] be 8c [2] a9 87 [2] b2 c9 [2] 8f }

  condition:
    any of them
}