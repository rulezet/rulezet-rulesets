rule TTP_XOR_MULT_DOSStub_dc25 {
  strings:
    $key_dc25 = { 88 4d [2] fc 55 [2] bb 57 [2] fc 46 [2] b2 4a [2] be 40 [2] a9 4b [2] b2 05 [2] 8f }

  condition:
    any of them
}