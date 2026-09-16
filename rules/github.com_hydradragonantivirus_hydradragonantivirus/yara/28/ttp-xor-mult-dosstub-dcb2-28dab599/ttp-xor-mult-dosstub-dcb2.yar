rule TTP_XOR_MULT_DOSStub_dcb2 {
  strings:
    $key_dcb2 = { 88 da [2] fc c2 [2] bb c0 [2] fc d1 [2] b2 dd [2] be d7 [2] a9 dc [2] b2 92 [2] 8f }

  condition:
    any of them
}