rule TTP_XOR_MULT_DOSStub_dc21 {
  strings:
    $key_dc21 = { 88 49 [2] fc 51 [2] bb 53 [2] fc 42 [2] b2 4e [2] be 44 [2] a9 4f [2] b2 01 [2] 8f }

  condition:
    any of them
}