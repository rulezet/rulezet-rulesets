rule TTP_XOR_MULT_DOSStub_dcac {
  strings:
    $key_dcac = { 88 c4 [2] fc dc [2] bb de [2] fc cf [2] b2 c3 [2] be c9 [2] a9 c2 [2] b2 8c [2] 8f }

  condition:
    any of them
}