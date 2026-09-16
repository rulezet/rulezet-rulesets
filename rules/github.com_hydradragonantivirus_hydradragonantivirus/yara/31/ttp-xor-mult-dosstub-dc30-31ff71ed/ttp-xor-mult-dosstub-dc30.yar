rule TTP_XOR_MULT_DOSStub_dc30 {
  strings:
    $key_dc30 = { 88 58 [2] fc 40 [2] bb 42 [2] fc 53 [2] b2 5f [2] be 55 [2] a9 5e [2] b2 10 [2] 8f }

  condition:
    any of them
}