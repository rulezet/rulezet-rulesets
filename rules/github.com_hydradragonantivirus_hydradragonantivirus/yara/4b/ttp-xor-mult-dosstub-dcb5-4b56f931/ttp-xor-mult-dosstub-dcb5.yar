rule TTP_XOR_MULT_DOSStub_dcb5 {
  strings:
    $key_dcb5 = { 88 dd [2] fc c5 [2] bb c7 [2] fc d6 [2] b2 da [2] be d0 [2] a9 db [2] b2 95 [2] 8f }

  condition:
    any of them
}