rule TTP_XOR_MULT_DOSStub_dcb7 {
  strings:
    $key_dcb7 = { 88 df [2] fc c7 [2] bb c5 [2] fc d4 [2] b2 d8 [2] be d2 [2] a9 d9 [2] b2 97 [2] 8f }

  condition:
    any of them
}