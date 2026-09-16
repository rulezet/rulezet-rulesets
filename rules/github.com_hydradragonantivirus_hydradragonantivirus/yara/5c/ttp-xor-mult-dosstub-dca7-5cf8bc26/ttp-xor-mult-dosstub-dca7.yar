rule TTP_XOR_MULT_DOSStub_dca7 {
  strings:
    $key_dca7 = { 88 cf [2] fc d7 [2] bb d5 [2] fc c4 [2] b2 c8 [2] be c2 [2] a9 c9 [2] b2 87 [2] 8f }

  condition:
    any of them
}