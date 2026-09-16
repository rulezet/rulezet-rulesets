rule TTP_XOR_MULT_DOSStub_dca3 {
  strings:
    $key_dca3 = { 88 cb [2] fc d3 [2] bb d1 [2] fc c0 [2] b2 cc [2] be c6 [2] a9 cd [2] b2 83 [2] 8f }

  condition:
    any of them
}